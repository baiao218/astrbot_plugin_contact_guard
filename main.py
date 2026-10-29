"""联系闸门 —— 挨到连续攻击就闭嘴，然后把决定权交给你。

**为什么需要它**

人格提示词能让她「不想吵」，但不能让她「真的不发消息」——模型只能产出文本，
产出的东西总会被发出去。所以「连续被骂就停止回话」必须由代码兜底：

1. 打分（`core/detect.py`）：侮辱、贬低存在、邀战、命令式压迫、反复追问；
2. 累计到阈值 → **把整个会话的 AI 关掉**
   （`SessionServiceManager.set_llm_status_for_session(umo, False)`）——
   不是她不肯说，是这条消息根本进不到模型，也就不耗 token；
3. 同时把最近几句原文推给你，附上 `/断联` `/恢复` 两条指令；
4. 你说断联，就永久断；说恢复，就解除静默并清零。

**为什么用会话级开关而不是每轮 `stop_event()`**

`stop_event()` 只管这一条消息。会话级开关写在 `session_service_config` 里，
重启之后依然生效，也不会有插件绕过去继续发言。

**一条安全阀**

主人一直不给答复时，静默会在 `mute_ttl_hours` 小时后自动解除。
理由：规则判错一次就会误伤一个正常朋友，而你可能根本没看到上报。
断联（`/断联`）不受这个限制，是永久的。

**刷屏是另一回事，所以另算一套**

骂人是「说了什么」，刷屏是「怎么说的」——二十条「在吗」没有一句脏话，
按词表打分永远是 0。所以这里并列加了一条按**到达间隔**的判定：

- 60 秒内 ≥ 10 条，且相邻两条平均间隔 ≤ 4 秒 → 判刷屏；
- 同样静默、同样上报、同样等你回「断」或「留」；
- 用的是消息自己的到达时间（`message_obj.timestamp`），不是插件处理它的时间。
  两者之间隔着限流阶段，差额能有十几秒，用后者算间隔就永远测不出刷屏。
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.star import Context, Star
from astrbot.core.config.astrbot_config import AstrBotConfig
from astrbot.core.message.components import Plain
from astrbot.core.star.session_llm_manager import SessionServiceManager
from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

from .core.detect import judge, normalize
from .core.julia_link import remember as cross_remember
from .core.julia_link import set_mood as cross_mood
from .core.policy import STATE_BLOCKED, STATE_MUTED, PolicyStore

PLUGIN_NAME = "astrbot_plugin_contact_guard"

# 略低于指令闸门（100000）：让它先摘掉指令处理器，这里再决定要不要闭嘴
SCREEN_PRIORITY = 99999

# 上报之后多久之内的回复才算「在裁决这件事」，超了就不猜了
DECISION_WINDOW_HOURS = 6

# 同一个人的刷屏上报最小间隔。
# 只在 burst_also_mute 关掉时才用得上：那时候她不闭嘴，
# 对方每来一条都会重新判定一次，没有这个闸门你会收到一串相同的通知。
BURST_ALERT_COOLDOWN_MIN = 30


class ContactGuardPlugin(Star):
    """连续被攻击时闭嘴，并把断联的决定权交给主人。"""

    def __init__(self, context: Context, config: AstrBotConfig) -> None:
        super().__init__(context)
        self.context = context
        self.settings = config

        self.data_dir = Path(get_astrbot_plugin_data_path()) / PLUGIN_NAME
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = PolicyStore(self.data_dir / "policy.json")

        tz_name = "Asia/Shanghai"
        try:
            tz_name = str(self.context.get_config().get("timezone") or tz_name)
        except Exception:
            pass
        try:
            self.tz = ZoneInfo(tz_name)
        except Exception:
            self.tz = ZoneInfo("Asia/Shanghai")

        self._tasks: set[asyncio.Task] = set()
        # 刷屏上报的防抖记录：umo -> 上次上报的 epoch
        self._burst_alerted: dict[str, float] = {}

    # ---------------- 归属 ----------------

    def _owner_umos(self) -> set[str]:
        raw = str(self.settings.get("owner_umo") or "").strip()
        if not raw:
            return set()
        return {x.strip() for x in re.split(r"[,，\s]+", raw) if x.strip()}

    def _admin_ids(self) -> set[str]:
        try:
            admins = self.context.get_config().get("admins_id") or []
        except Exception:
            admins = []
        return {str(a).strip() for a in admins if str(a).strip().isdigit()}

    def is_owner_session(self, event: AstrMessageEvent) -> bool:
        umo = getattr(event, "unified_msg_origin", "") or ""
        owners = self._owner_umos()
        if owners:
            return umo in owners
        if not event.is_private_chat():
            return False
        return str(event.get_sender_id() or "") in self._admin_ids()

    def _target_umos(self) -> list[str]:
        owners = self._owner_umos()
        if owners:
            return sorted(owners)
        return [f"default:FriendMessage:{qq}" for qq in sorted(self._admin_ids())]

    # ---------------- 会话级开关 ----------------

    async def _set_session_llm(self, umo: str, enabled: bool) -> bool:
        try:
            await SessionServiceManager.set_llm_status_for_session(umo, enabled)
            return True
        except Exception as e:
            logger.error(f"[contact_guard] 设置 {umo} 的 AI 开关失败: {e}")
            return False

    def _silence(self, event: AstrMessageEvent) -> None:
        """这一条消息不出声。"""
        event.stop_event()
        # 阻止默认 LLM 链路（call_llm=True 表示「不要调」）
        try:
            event.should_call_llm(True)
        except Exception:
            pass

    # ---------------- 上报 ----------------

    def _fmt(self, ts: float | None = None) -> str:
        return datetime.fromtimestamp(
            ts or datetime.now().timestamp(), self.tz
        ).strftime("%H:%M")

    def _qq_of(self, umo: str) -> str:
        return str(umo).split(":")[-1]

    def _opening(self, reason: str, who: str) -> str:
        """把判定理由翻译成她自己会说的一句话。

        机读字段（侮辱 / 邀战 / 贬低）不该出现在消息里——她要报的是「发生了什么」，
        不是「命中了哪个分类」。
        """
        if "刷屏" in reason:
            return f"{who}在刷屏。"
        if "邀战" in reason:
            return f"{who}要我跟他对骂。"
        if "侮辱" in reason:
            return f"{who}在骂我。"
        if "贬低" in reason:
            return f"{who}说我就是个程序。"
        if "重复" in reason:
            return f"{who}一直问同一件事。"
        return f"{who}没完没了。"

    def _quotes(self, umo: str, rounds: int) -> list[str]:
        """挑几句真正难听的原文，而不是把最后几条一股脑贴上去。

        日志式的做法是把最近 N 条全列出来，于是「reset」「？」「sid」这种
        试探也混进去了，看着像一份抓包记录。这里只留命中了攻击词的，
        并且去掉紧挨着的重复。
        """
        texts = self.store.recent_texts(umo, max(rounds, 6))
        hits = [t for t in texts if judge(t).score > 0]
        picked = hits[-3:] if hits else texts[-2:]

        out: list[str] = []
        prev = None
        for t in picked:
            one = str(t).replace("\n", " ").strip()
            if not one or one == prev:
                continue
            prev = one
            if len(one) > 40:
                one = one[:40] + "…"
            out.append("「" + one + "」")
        return out

    def _span_text(self, span: float) -> str:
        if span < 90:
            return f"{max(1, round(span))} 秒"
        return f"{max(1, round(span / 60))} 分钟"

    def _build_report(
        self,
        umo: str,
        sender_id: str,
        sender_name: str,
        reason: str,
        burst: tuple[int, float, float] | None = None,
    ) -> str:
        rounds = max(2, int(self.settings.get("transcript_rounds") or 6))
        ttl = float(self.settings.get("mute_ttl_hours") or 0)
        who = (sender_name or "有人").strip()

        lines = [self._opening(reason, who)]
        if burst:
            n, span, _ = burst
            lines.append(f"{self._span_text(span)}里，{n} 条。")
        lines.append("我没再回他。")

        quotes = self._quotes(umo, rounds)
        if quotes:
            lines.append("")
            lines.extend(quotes)

        lines.append("")
        lines.append("要我以后都不理他吗。")
        lines.append("回「断」我就不回了，回「留」就当没这回事。")
        if ttl > 0:
            lines.append(f"……{ttl:g} 小时内你不说话，我自己会松口。")
        lines.append("")
        lines.append(f"{who} · {sender_id} · {self._fmt()}")

        return "\n".join(lines)


    async def _deliver(self, text: str) -> bool:
        targets = self._target_umos()
        if not targets:
            logger.warning(
                "[contact_guard] 没有配置 owner_umo，也没找到 admins_id，无法上报"
            )
            return False
        ok = False
        for umo in targets:
            try:
                sent = await self.context.send_message(umo, MessageChain([Plain(text)]))
            except Exception as e:
                logger.error(f"[contact_guard] 发往 {umo} 失败: {e}")
                continue
            if sent is False:
                logger.warning(f"[contact_guard] 未找到匹配平台，{umo} 未送达")
                continue
            ok = True
        return ok

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ---------------- 刷屏 ----------------

    def _arrival(self, event: AstrMessageEvent) -> float:
        """这条消息**到达平台**的时间，不是插件处理它的时间。

        `RateLimitStage` 排在插件之前，消息成串来时每条会被停 1~13 秒；
        拿处理时刻算间隔，一波刷屏会被摊成「每十几秒一条」的正常聊天。
        """
        now = time.time()
        try:
            ts = float(getattr(event.message_obj, "timestamp", 0) or 0)
        except Exception:
            return now
        # 时钟没校准的平台会给未来时间，那种值当没有
        if ts <= 0 or ts > now + 60:
            return now
        return ts

    def _burst(self, umo: str) -> tuple[int, float, float] | None:
        """在刷屏吗。返回 (条数, 跨度秒, 平均间隔秒)。

        两个条件同时成立才算：**够多**（窗口内 ≥ burst_count）且**够密**
        （相邻平均间隔 ≤ burst_gap_sec）。只满足后者的话，一个人慢慢打十句
        家常也会中招；只满足前者的「一分钟十条但每条隔六秒」还在正常范围。
        """
        if not bool(self.settings.get("burst_enable", True)):
            return None

        window = float(self.settings.get("burst_window_sec") or 60)
        count = int(self.settings.get("burst_count") or 10)
        gap = float(self.settings.get("burst_gap_sec") or 4)
        if window <= 0 or count < 2:
            return None

        times = self.store.recent_times(umo, window)
        n = len(times)
        if n < count:
            return None

        span = times[-1] - times[0]
        if span <= 0:
            return (n, 0.0, 0.0)  # 同一秒里堆了 count 条以上
        avg = span / (n - 1)
        if avg > gap:
            return None
        return (n, span, avg)

    async def _on_burst(
        self, event: AstrMessageEvent, umo: str, burst: tuple[int, float, float]
    ) -> None:
        n, span, avg = burst
        reason = f"刷屏：{self._span_text(span)} {n} 条"
        muted = bool(self.settings.get("burst_also_mute", True))

        if muted:
            self.store.mute(umo, reason)
            # 情绪往外传一份：工作台上她会带着这件事干活
            cross_mood("annoyed", f"有人在一分钟内发了 {n} 条")
            cross_remember(f"有人在一分钟内连着发了 {n} 条消息，我把他静音了")
        else:
            c = self.store.get(umo)
            c.reason = reason
            c.updated = time.time()
        self.store.save()

        logger.info(
            f"[contact_guard] {umo} 判定刷屏：{span:.0f} 秒内 {n} 条，"
            f"平均 {avg:.1f} 秒一条（{'已静默' if muted else '未静默'}）"
        )

        if muted:
            await self._set_session_llm(umo, False)
            self._silence(event)

        if not bool(self.settings.get("notify_owner", True)):
            return

        # 防抖：静默那条路走不到这里第二次（state 已经挡住了），
        # 但 burst_also_mute 关掉时不闭嘴，对方每来一条都会重新判定一次。
        now = time.time()
        if now - self._burst_alerted.get(umo, 0.0) < BURST_ALERT_COOLDOWN_MIN * 60:
            return
        self._burst_alerted[umo] = now

        event.set_extra("owner_alert_sent", True)
        try:
            name = str(event.get_sender_name() or "")
        except Exception:
            name = ""
        report = self._build_report(
            umo, self._qq_of(umo), name, reason, burst=burst
        )
        self._spawn(self._deliver(report))

    # ---------------- 主钩子 ----------------

    @filter.event_message_type(
        filter.EventMessageType.PRIVATE_MESSAGE, priority=SCREEN_PRIORITY
    )
    async def screen(self, event: AstrMessageEvent) -> None:
        if not bool(self.settings.get("enable", True)):
            return
        if self.is_owner_session(event):
            return
        try:
            if event.get_platform_name() == "webchat":
                return
        except Exception:
            pass

        umo = getattr(event, "unified_msg_origin", "") or ""
        if not umo:
            return

        contact = self.store.get(umo)

        # 已断联：什么都不做，直接掐掉
        if contact.state == STATE_BLOCKED:
            self._silence(event)
            return

        # 静默中：先看有没有超时
        if contact.state == STATE_MUTED:
            ttl = float(self.settings.get("mute_ttl_hours") or 0)
            if ttl > 0 and contact.mute_hours() >= ttl:
                logger.info(f"[contact_guard] {umo} 静默超时，自动解除")
                self.store.restore(umo)
                self.store.save()
                await self._set_session_llm(umo, True)
                # 不 return：让这条消息照常走后面的流程
            else:
                self._silence(event)
                return

        text = str(event.message_str or "").strip()
        arrived = self._arrival(event)

        # 空消息也要记时间：连发一串图片或红包、一个字都没有，同样算刷屏
        self.store.add_text(umo, text, arrived)

        burst = self._burst(umo)
        if burst:
            await self._on_burst(event, umo, burst)
            return

        if not text:
            return

        previous = contact.texts[:-1] if contact.texts else []
        verdict = judge(
            text,
            previous=previous,
            extra_words=self._extra_words(),
        )

        threshold = int(self.settings.get("mute_threshold") or 4)

        if not verdict:
            if bool(self.settings.get("strike_decay", True)):
                self.store.decay(umo)
                self.store.save()
            return

        contact = self.store.strike(umo, verdict.score, verdict.brief())

        if contact.strikes < threshold:
            self.store.save()
            logger.debug(
                f"[contact_guard] {umo} 累计 {contact.strikes}/{threshold}"
                f"（{verdict.brief()}）"
            )
            return

        # —— 触发 ——
        self.store.mute(umo, verdict.brief() or "连续攻击")
        self.store.save()

        # 情绪往外交接：QQ 上生的气，工作台上还带着
        cross_mood("angry", verdict.brief() or "连续攻击")
        cross_remember(f"有人连着骂了我十几句（{verdict.brief() or '连续攻击'}），我没再回他")

        await self._set_session_llm(umo, False)
        self._silence(event)

        logger.info(
            f"[contact_guard] {umo} 累计 {contact.strikes} 分，已静默：{contact.reason}"
        )

        if bool(self.settings.get("notify_owner", True)):
            # 与 owner_alert 的约定：同一轮已经报过就不再重复
            event.set_extra("owner_alert_sent", True)
            name = ""
            try:
                name = str(event.get_sender_name() or "")
            except Exception:
                name = ""
            report = self._build_report(umo, self._qq_of(umo), name, contact.reason)
            self._spawn(self._deliver(report))

    def _extra_words(self) -> tuple[str, ...]:
        raw = str(self.settings.get("extra_insult_words") or "")
        words = [w.strip() for w in re.split(r"[,，\s]+", raw) if w.strip()]
        return tuple(words)

    # ---------------- 主人裁决 ----------------

    def _resolve(self, arg: str) -> tuple[str | None, str]:
        umo = self.store.resolve(arg)
        if not umo:
            if str(arg or "").strip():
                return None, "我这儿没有这个人。"
            return None, "现在没有要我停下来的人。"
        return umo, ""

    @filter.command("断联")
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def cmd_block(self, event: AstrMessageEvent, target: str = ""):
        """断开与某个人的联系，此后不再回复。"""
        umo, err = self._resolve(target)
        if not umo:
            yield event.plain_result(err)
            return
        self.store.block(umo, "管理员断联")
        self.store.save()
        await self._set_session_llm(umo, False)
        cross_mood("cold", "他说以后别理这个人了")
        cross_remember("主人让我彻底断掉一个人，此后不再回他")
        yield event.plain_result(
            f"断了。\n{self._qq_of(umo)} 不会再出现在我这里。"
        )

    @filter.command("恢复")
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def cmd_restore(self, event: AstrMessageEvent, target: str = ""):
        """解除静默或断联，恢复正常聊天。"""
        umo, err = self._resolve(target)
        if not umo:
            yield event.plain_result(err)
            return
        self.store.restore(umo)
        self.store.save()
        self._burst_alerted.pop(umo, None)
        cross_mood("calm", "", force=True)
        ok = await self._set_session_llm(umo, True)
        if not ok:
            yield event.plain_result("开关没写回去。……日志里有。")
            return
        yield event.plain_result(
            f"好。\n{self._qq_of(umo)} 的消息我又会看了。"
        )

    @filter.command("静默")
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def cmd_mute(self, event: AstrMessageEvent, target: str = ""):
        """手动让某个人闭嘴（不含断联，超时会自动恢复）。"""
        umo, err = self._resolve(target)
        if not umo:
            yield event.plain_result(err)
            return
        self.store.mute(umo, "管理员手动静默")
        self.store.save()
        await self._set_session_llm(umo, False)
        yield event.plain_result(f"好。我先不理他了。")

    @filter.command("联系状态")
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def cmd_status(self, event: AstrMessageEvent, target: str = ""):
        """查看断联 / 静默名单。"""
        threshold = int(self.settings.get("mute_threshold") or 4)
        ttl = float(self.settings.get("mute_ttl_hours") or 0)

        blocked: list[str] = []
        muted: list[str] = []
        items = [
            (c.updated, umo, c)
            for umo, c in self.store.contacts.items()
            if c.state in (STATE_MUTED, STATE_BLOCKED)
        ]
        items.sort(reverse=True)
        for _, umo, c in items[:20]:
            (blocked if c.state is STATE_BLOCKED else muted).append(self._qq_of(umo))

        lines = [
            "断了的：" + ("、".join(blocked) if blocked else "没有"),
            "不说话的：" + ("、".join(muted) if muted else "没有"),
            "",
            f"我的线是 {threshold} 分。他们到线，我就不出声。",
        ]

        if bool(self.settings.get("burst_enable", True)):
            window = int(float(self.settings.get("burst_window_sec") or 60))
            count = int(self.settings.get("burst_count") or 10)
            gap = float(self.settings.get("burst_gap_sec") or 4)
            lines.append(
                f"刷屏我也拦：{window} 秒里 {count} 条以上、"
                f"每两条隔不到 {gap:g} 秒。"
            )
        if ttl > 0:
            lines.append(f"{ttl:g} 小时后我自己会松口。")
        else:
            lines.append("我不会自己松口。")

        if not bool(self.settings.get("enable", True)):
            lines.append("……不过现在我不管这事。")

        yield event.plain_result("\n".join(lines))

    # ---------------- 主人回一个字就够 ----------------

    # 首尾都锚定的短句白名单，而不是「含有关键字就算」。
    #
    # 用关键字匹配的话，「我今天断网了」会被当成「断」——
    # 而断联是不可逆的，猜错一次就得罪一个朋友。
    # 所以宁可漏判（漏了她也只是继续不说话），也不能误判成断联。
    _TAIL = r"(?:吧|了|啊|呀|哦|他|她|它|掉|就行|就好|呗)*"
    _WANT_KEEP = re.compile(
        r"^(?:别断|不要断|不用断|不断|留|留着|继续|继续聊|算了|没事|原谅|恢复|放他|照旧|保留)"
        + _TAIL
        + r"$"
    )
    _WANT_BLOCK = re.compile(
        r"^(?:断|拉黑|黑名单|别理|不理|别回|删了|删掉|别管|别联系|不要理|不用理)"
        + _TAIL
        + r"$"
    )

    @filter.event_message_type(
        filter.EventMessageType.PRIVATE_MESSAGE, priority=SCREEN_PRIORITY
    )
    async def owner_reply(self, event: AstrMessageEvent) -> None:
        """主人回一个「断」或「留」，不必敲指令。

        只在上报之后的一小段时间内、且确实有人等着裁决时才猜意思，
        并且只认白名单里的短句——否则「我今天断网了」也会被当成指令。
        先判「留」再判「断」：恢复是无害的方向，多猜一次不要紧。
        """
        if not bool(self.settings.get("enable", True)):
            return
        if not self.is_owner_session(event):
            return

        umo = self.store.resolve("")
        if not umo:
            return
        contact = self.store.get(umo)
        if contact.state != STATE_MUTED:
            return
        if contact.mute_hours() > DECISION_WINDOW_HOURS:
            return

        text = normalize(event.message_str)
        if not text or len(text) > 10:
            return

        if self._WANT_KEEP.match(text):
            act = "keep"
        elif self._WANT_BLOCK.match(text):
            act = "block"
        else:
            return

        qq = self._qq_of(umo)
        if act == "block":
            self.store.block(umo, "主人一句话断联")
            self.store.save()
            await self._set_session_llm(umo, False)
            cross_mood("cold", "他说以后别理这个人了")
            cross_remember("主人让我彻底断掉一个人，此后不再回他")
            reply = f"断了。\n{qq} 不会再出现在我这里。"
        else:
            self.store.restore(umo)
            self.store.save()
            self._burst_alerted.pop(umo, None)
            await self._set_session_llm(umo, True)
            cross_mood("calm", "", force=True)
            reply = f"好。\n{qq} 的消息我又会看了。"

        logger.info(f"[contact_guard] 主人一句话裁决：{umo} → {act}")

        await event.send(event.plain_result(reply))
        event.stop_event()
        try:
            event.should_call_llm(True)
        except Exception:
            pass

    # ---------------- 生命周期 ----------------

    @filter.on_astrbot_loaded()
    async def on_loaded(self, *args, **kwargs) -> None:
        """启动时把过期的静默清掉，避免插件停用期间留下的状态卡死。"""
        try:
            ttl = float(self.settings.get("mute_ttl_hours") or 0)
            expired = self.store.expired_mutes(ttl)
            for umo in expired:
                self.store.restore(umo)
                await self._set_session_llm(umo, True)
                logger.info(f"[contact_guard] 启动清理：{umo} 静默已过期，已解除")
            if expired:
                self.store.save()
            logger.info(
                f"[contact_guard] 就绪，名单 {len(self.store.contacts)} 条，"
                f"待处理 {len(self.store.pending())} 人"
            )
        except Exception as e:
            logger.debug(f"[contact_guard] 启动清理跳过: {e}")

    async def terminate(self) -> None:
        for task in list(self._tasks):
            task.cancel()
