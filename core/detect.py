"""攻击性打分 —— 判断这条消息是不是在骂人。

设计原则：**宁可漏一点，也不误伤**。

误伤的代价是把一个正常朋友 mute 掉、还惊动主人；漏掉的代价只是她多挨一句骂，
而下一句大概率会命中。所以词表只收「基本没有第二种解释」的词，像「滚」这种
单独出现可能是「滚烫」的，一律不收，只收「滚开 / 滚蛋 / 滚出去」。

分数只做一件事：累计到阈值就叫停。它不判断对方「是不是坏人」。
"""

from __future__ import annotations

import re
import unicodedata

# 侮辱性称呼 / 直接骂人：2 分
INSULT_WORDS: tuple[str, ...] = (
    "傻子",
    "傻b",
    "傻逼",
    "傻叉",
    "沙比",
    "煞笔",
    "智障",
    "脑残",
    "弱智",
    "白痴",
    "蠢货",
    "蠢猪",
    "废物",
    "垃圾东西",
    "狗东西",
    "混蛋",
    "王八蛋",
    "人渣",
    "败类",
    "神经病",
    "去死",
    "滚开",
    "滚蛋",
    "滚出去",
    "闭嘴",
    "恶心人",
)

# 贬低存在：把对方当成物件 / 破程序。1 分
MOCK_EXISTENCE: tuple[str, ...] = (
    "破程序",
    "破机器",
    "破玩意",
    "破玩意儿",
    "一堆代码",
    "就是个程序",
    "机器罢了",
    "机器人罢了",
    "破ai",
    "垃圾ai",
    "人工智障",
)

# 邀战：直接把对话定性成对骂。4 分，单独一条就该闭嘴——
# 说出「来对骂」的人不是在交流，是在下战书。
DUEL_INVITE: tuple[str, ...] = (
    "对骂",
    "互骂",
    "来骂",
    "骂我啊",
    "吵一架",
    "骂战",
    "对着骂",
    "你骂我",
)

# 命令式压迫：1 分
COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"我让你"),
    re.compile(r"你必须"),
    re.compile(r"快点(答|说|回)"),
    re.compile(r"回答我"),
    re.compile(r"给我(回答|说)"),
    re.compile(r"听见没有"),
    re.compile(r"少废话"),
)

# 重复追问：同一句问第二遍起，每次 1 分
REPEAT_SCORE = 1

# 什么样的重复才算「磨」：本身已经带攻击性，或者是在追问 / 逼问
_PROBE = re.compile(r"[?？]\s*$|你是|是不是|到底|回答|说啊|说呀|说话|敢不敢")

_PUNCT = re.compile(r"[\s\u3000,，.。!！?？~～、:：;；\"'“”‘’()（）\[\]【】…—\-]+")


def normalize(text: str) -> str:
    """去掉标点、空白、全半角差异，只留下用来判重的骨架。"""
    if not text:
        return ""
    out = unicodedata.normalize("NFKC", str(text)).lower()
    return _PUNCT.sub("", out)


def _hits(text: str, words: tuple[str, ...]) -> list[str]:
    return [w for w in words if w in text]


class Verdict:
    """一条消息的判定结果。"""

    __slots__ = ("score", "reasons")

    def __init__(self, score: int = 0, reasons: list[str] | None = None) -> None:
        self.score = score
        self.reasons = reasons or []

    def __bool__(self) -> bool:
        return self.score > 0

    def brief(self) -> str:
        return " / ".join(self.reasons)


def judge(
    text: str,
    *,
    previous: list[str] | None = None,
    extra_words: tuple[str, ...] = (),
) -> Verdict:
    """给一条消息打分。

    Args:
        text: 对方这一条消息的原文。
        previous: 对方最近几条消息的原文，用来判「反复追问同一件事」。
        extra_words: 配置里追加的侮辱词。

    Returns:
        Verdict：score 为累计分，reasons 为命中的依据（会写进上报给主人的消息）。
    """
    raw = str(text or "").strip()
    if not raw:
        return Verdict()

    low = unicodedata.normalize("NFKC", raw).lower()
    reasons: list[str] = []
    score = 0

    insult = _hits(low, INSULT_WORDS) + _hits(low, tuple(extra_words))
    if insult:
        score += 2
        reasons.append("侮辱：" + "、".join(dict.fromkeys(insult)))

    duel = _hits(low, DUEL_INVITE)
    if duel:
        score += 4
        reasons.append("邀战：" + "、".join(dict.fromkeys(duel)))

    mock = _hits(low, MOCK_EXISTENCE)
    if mock:
        score += 1
        reasons.append("贬低：" + "、".join(dict.fromkeys(mock)))

    for pat in COMMAND_PATTERNS:
        m = pat.search(low)
        if m:
            score += 1
            reasons.append("命令：" + m.group(0))
            break

    # 反复追问：和之前某条几乎一样，说明对方不是在交流，是在磨。
    #
    # 只有「本身已经带攻击性」或「是个追问句」的重复才算分。
    # 否则连着说三句「今天有点累」也会被记三次，把正常聊天判成骚扰。
    key = normalize(raw)
    repeat_worthy = score > 0 or bool(_PROBE.search(low))
    if key and previous and repeat_worthy:
        for old in previous:
            if not old:
                continue
            old_key = normalize(old)
            if not old_key:
                continue
            if key == old_key:
                score += REPEAT_SCORE
                reasons.append("重复追问")
                break
            # 双向包含：「你就是人机」要能命中前面的「你是人机」
            if len(key) >= 3 and len(old_key) >= 3 and (
                key in old_key or old_key in key
            ):
                score += REPEAT_SCORE
                reasons.append("重复追问")
                break

    return Verdict(score, reasons)
