"""联系人策略存储 —— 谁被静默、谁被断联。

只存在本地 JSON 里，不做数据库。理由：条目很少（一辈子也就几十个），
而且出问题时你要能直接打开文件改。原子写入，崩了也不会留半个文件。
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

STATE_NORMAL = "normal"
STATE_MUTED = "muted"
STATE_BLOCKED = "blocked"

MAX_TEXTS = 8

# 每条消息的到达时刻。判定刷屏要用它，所以留得比文本多一些——
# 文本只留 8 条是为了给主人看，时间戳留 24 条是为了能算清「一分钟几条」。
MAX_TIMES = 24


class Contact:
    """一个人的处理策略。"""

    __slots__ = (
        "state",
        "strikes",
        "muted_at",
        "updated",
        "reason",
        "texts",
        "times",
    )

    def __init__(self, data: dict | None = None) -> None:
        data = data or {}
        self.state: str = str(data.get("state") or STATE_NORMAL)
        self.strikes: int = int(data.get("strikes") or 0)
        self.muted_at: float = float(data.get("muted_at") or 0.0)
        self.updated: float = float(data.get("updated") or 0.0)
        self.reason: str = str(data.get("reason") or "")
        self.texts: list[str] = [str(t) for t in (data.get("texts") or [])][-MAX_TEXTS:]
        self.times: list[float] = [
            float(t) for t in (data.get("times") or []) if float(t) > 0
        ][-MAX_TIMES:]

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "strikes": self.strikes,
            "muted_at": self.muted_at,
            "updated": self.updated,
            "reason": self.reason,
            "texts": self.texts[-MAX_TEXTS:],
            "times": self.times[-MAX_TIMES:],
        }

    # ---- 便捷判定 ----

    @property
    def is_blocked(self) -> bool:
        return self.state == STATE_BLOCKED

    @property
    def is_muted(self) -> bool:
        """静默中（含断联）。两种情况都不出声。"""
        return self.state in (STATE_MUTED, STATE_BLOCKED)

    def mute_hours(self) -> float:
        if not self.muted_at:
            return 0.0
        return (time.time() - self.muted_at) / 3600.0


class PolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.contacts: dict[str, Contact] = {}
        self.load()

    # ---- 读写 ----

    def load(self) -> None:
        self.contacts = {}
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        for umo, data in (raw.get("contacts") or {}).items():
            try:
                self.contacts[str(umo)] = Contact(data)
            except Exception:
                continue

    def save(self) -> None:
        payload = {
            "version": 1,
            "contacts": {k: v.to_dict() for k, v in self.contacts.items()},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".policy-", suffix=".tmp"
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except Exception:
                pass
            raise

    # ---- 查询 ----

    def get(self, umo: str) -> Contact:
        c = self.contacts.get(umo)
        if c is None:
            c = Contact()
            self.contacts[umo] = c
        return c

    def recent_texts(self, umo: str, n: int = 6) -> list[str]:
        return self.get(umo).texts[-n:]

    def pending(self) -> list[str]:
        """已经静默、还没被主人裁决的会话，新的在前。"""
        items = [
            (c.muted_at, umo)
            for umo, c in self.contacts.items()
            if c.state == STATE_MUTED
        ]
        items.sort(reverse=True)
        return [umo for _, umo in items]

    def handled(self) -> list[str]:
        """所有非正常状态（静默 + 断联），最近动过的在前。

        `/断联` `/恢复` 不带参数时取这里的第一个 —— 只算静默的话，
        一旦断联就再也 `/恢复` 不回来了。
        """
        items = [
            (c.updated, umo)
            for umo, c in self.contacts.items()
            if c.state in (STATE_MUTED, STATE_BLOCKED)
        ]
        items.sort(reverse=True)
        return [umo for _, umo in items]

    def resolve(self, arg: str) -> str | None:
        """把主人给的「QQ 号 / 会话 ID / 空」解析成 umo。"""
        arg = str(arg or "").strip()
        if not arg:
            items = self.handled()
            return items[0] if items else None
        if arg in self.contacts:
            return arg
        # 当成 QQ 号：找 umo 结尾是 ":<qq>" 的
        for umo in self.contacts:
            if umo.endswith(":" + arg) or umo.split(":")[-1] == arg:
                return umo
        return None

    # ---- 修改 ----

    def add_text(self, umo: str, text: str, ts: float | None = None) -> None:
        """记一条消息。

        `ts` 必须是**消息到达平台的时间**，不是插件处理这条消息的时间。
        中间隔着限流阶段，差额能有十几秒，用处理时间算间隔就永远测不出刷屏。
        """
        c = self.get(umo)
        text = str(text or "").strip()
        now = float(ts if ts is not None else time.time())
        if now <= 0:
            now = time.time()

        # 时间戳永远记，哪怕这条是空的——空消息（图片、红包）也算一次「刷」。
        c.times.append(now)
        if len(c.times) > MAX_TIMES:
            del c.times[:-MAX_TIMES]

        if not text:
            return
        c.texts.append(text)
        if len(c.texts) > MAX_TEXTS:
            del c.texts[:-MAX_TEXTS]

    def recent_times(self, umo: str, window: float) -> list[float]:
        """最近 `window` 秒内的到达时刻，早的在前。

        基准取「已知最晚的一条到达时间」，不是 `time.time()`：
        限流会把这批消息的处理推后十几秒，拿处理时刻做减法，
        本该落在窗口里的消息会被算成「很久以前」，刷屏就漏了。
        """
        c = self.get(umo)
        if not c.times:
            return []
        base = max(c.times)
        return sorted(t for t in c.times if base - t <= window)

    def strike(self, umo: str, score: int, reason: str) -> Contact:
        c = self.get(umo)
        c.strikes += max(1, score)
        c.reason = reason
        c.updated = time.time()
        return c

    def decay(self, umo: str, amount: int = 1) -> Contact:
        c = self.get(umo)
        c.strikes = max(0, c.strikes - max(1, amount))
        c.updated = time.time()
        return c

    def mute(self, umo: str, reason: str) -> Contact:
        c = self.get(umo)
        c.state = STATE_MUTED
        c.muted_at = time.time()
        c.reason = reason
        c.updated = c.muted_at
        return c

    def block(self, umo: str, reason: str = "") -> Contact:
        c = self.get(umo)
        c.state = STATE_BLOCKED
        c.muted_at = c.muted_at or time.time()
        if reason:
            c.reason = reason
        c.updated = time.time()
        return c

    def restore(self, umo: str) -> Contact:
        c = self.get(umo)
        c.state = STATE_NORMAL
        c.strikes = 0
        c.muted_at = 0.0
        c.reason = ""
        c.updated = time.time()
        return c

    def expired_mutes(self, ttl_hours: float) -> list[str]:
        """静默超时、且主人一直没裁决的会话。"""
        if ttl_hours <= 0:
            return []
        return [
            umo
            for umo, c in self.contacts.items()
            if c.state == STATE_MUTED and c.mute_hours() >= ttl_hours
        ]
