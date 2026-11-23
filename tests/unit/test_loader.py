"""十条契约测试：每条对应 README 列出的一个缺陷。"""

import base64
import hmac
import json
import pickle

import pytest

from guard.loader import (
    decode_blob,
    depth_ok,
    load_batch,
    rebuild,
    safe_load,
    type_allowed,
    validate_policy,
    verify_signature,
)

KEY = b"unit-contract-key"
SAFE_ALLOW = ("dict", "list", "str", "int", "float", "bool", "NoneType")
POLICY = {"allow": SAFE_ALLOW, "max_depth": 4, "require_signature": True}

_CALLS = []


def _marker():
    _CALLS.append("pickle executed")


class _Bomb:
    def __reduce__(self):
        return (_marker, ())


def _dangerous_callable():
    return None


def _envelope(payload_obj, key=KEY, extra=None, tamper=False):
    raw = pickle.dumps(payload_obj, protocol=4)
    payload_b64 = base64.b64encode(raw).decode("ascii")
    signature = hmac.new(key, payload_b64.encode("ascii"), "sha256").hexdigest()
    if tamper:
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]
    envelope = {
        "version": 1,
        "encoding": "pickle",
        "payload": payload_b64,
        "signature": signature,
    }
    if extra:
        envelope.update(extra)
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_defect_01_signature_is_checked_before_pickle_loads():
    """缺陷 1：验签必须早于反序列化，伪造签名不能触发构造副作用。"""
    _CALLS.clear()
    blob = _envelope(_Bomb(), tamper=True)

    with pytest.raises(ValueError):
        safe_load(blob, POLICY, KEY)

    assert _CALLS == []


def test_defect_02_signature_uses_constant_time_compare(monkeypatch):
    """缺陷 2：签名比较必须走 hmac.compare_digest，而不是普通等号。"""
    calls = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    blob = _envelope({"ok": True})

    assert verify_signature(blob, KEY) is True
    assert calls


def test_defect_03_type_whitelist_checks_nested_values():
    """缺陷 3：类型白名单必须递归检查字典和列表内部。"""
    value = {"outer": [{"inner": _dangerous_callable}]}

    assert type_allowed(value, SAFE_ALLOW) is False


def test_defect_04_policy_rejects_executable_allowlist():
    """缺陷 4：白名单里出现可执行类型时必须报策略问题。"""
    policy = {
        "allow": ("dict", "function"),
        "max_depth": 4,
        "require_signature": True,
    }

    issues = validate_policy(policy)

    assert "executable_type" in issues


def test_defect_05_depth_check_counts_dict_nesting():
    """缺陷 5：深度检测必须统计字典层数，不能只数列表。"""
    value = {"a": {"b": {"c": 1}}}

    assert depth_ok(value, 2) is False


def test_defect_06_depth_limit_rejects_one_level_over():
    """缺陷 6：恰好到上限可通过，超过一级必须拒绝。"""
    assert depth_ok({"a": 1}, 1) is True
    assert depth_ok({"a": {"b": 1}}, 1) is False


def test_defect_07_rebuild_never_passes_unknown_types_through():
    """缺陷 7：重建遇到未知类型必须抛异常，不能原样返回。"""
    value = {"known": [1, "x"], "unknown": object()}

    with pytest.raises(ValueError):
        rebuild(value, ("dict", "list", "str", "int"))


def test_defect_08_policy_validation_requires_signature():
    """缺陷 8：策略校验必须检查强制验签，缺失或为假都算问题。"""
    missing = {"allow": SAFE_ALLOW, "max_depth": 4}
    disabled = {"allow": SAFE_ALLOW, "max_depth": 4, "require_signature": False}

    assert "signature_not_required" in validate_policy(missing)
    assert "signature_not_required" in validate_policy(disabled)


def test_defect_09_batch_rechecks_each_signature():
    """缺陷 9：批量加载不能复用前一项的验签结果。"""
    good = _envelope({"ok": True})
    forged = _envelope("forged-value", tamper=True)

    result = load_batch({"good": good, "forged": forged}, POLICY, KEY)

    assert result["good"] == {"ok": True}
    assert isinstance(result["forged"], ValueError)


def test_defect_10_decode_blob_rejects_extra_fields():
    """缺陷 10：严格解码不得静默忽略多余字段。"""
    blob = _envelope({"ok": True}, extra={"debug": True})

    with pytest.raises(ValueError):
        decode_blob(blob)
