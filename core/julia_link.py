"""把情绪同步到跨端共享状态。

这个插件（contact_guard）决定"她该不该闭嘴"，
但"她现在是什么心情"要能被另一个端（工作台）看到——所以在这里开一个口子。

**故意做成松耦合**：加载不到 `~/.julia/julia_state.py` 就静默跳过，
一行日志都不刷。跨端同步是锦上添花，不该让联系闸门因为它的缺失而失效。
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

# JULIA_HOME 是给测试用的隔离口：不设就走真实的 ~/.julia。
_SEED = (
    Path(os.environ.get("JULIA_HOME") or Path.home() / ".julia") / "julia_state.py"
)
_MOD = None
_TRIED = False

# 情绪轻重。数字大的不会被小的盖掉。
_RANK = {"calm": 0, "annoyed": 1, "fond": 2, "tired": 2, "angry": 3, "cold": 4}


def _load():
    global _MOD, _TRIED
    if _TRIED:
        return _MOD
    _TRIED = True
    if not _SEED.exists():
        return None
    try:
        name = "julia_state_shared"
        if name in sys.modules:
            _MOD = sys.modules[name]
            return _MOD
        spec = importlib.util.spec_from_file_location(name, _SEED)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        _MOD = mod
    except Exception:
        _MOD = None
    return _MOD


def set_mood(mood: str, reason: str = "", force: bool = False) -> bool:
    """写情绪。成功返回 True；没装共享模块时返回 False，不抛异常。

    带一道"不降级"保护：被骂生气之后，对方再刷几条屏不该把情绪冲淡成
    「有点烦」。只有明确 calm（恢复联系）才允许压过去，所以那条要 force。
    """
    mod = _load()
    if mod is None:
        return False
    try:
        if not force:
            cur = str(mod.load_state().get("mood") or "calm")
            if _RANK.get(mood, 0) < _RANK.get(cur, 0):
                return False
        mod.set_mood(mood, reason)
        return True
    except Exception:
        return False


def remember(text: str, source: str = "QQ") -> bool:
    mod = _load()
    if mod is None:
        return False
    try:
        return bool(mod.remember(source, text))
    except Exception:
        return False
