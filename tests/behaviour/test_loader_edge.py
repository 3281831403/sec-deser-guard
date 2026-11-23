"""五条边界测试：合法封装、伪造签名、危险类型、深度炸弹、批次独立。"""

import base64
import hmac
import json
import pickle

import pytest

from guard.loader import load_batch, safe_load, verify_signature

KEY = b"behaviour-edge-key"
SAFE_ALLOW = ("dict", "list", "str", "int", "float", "bool", "NoneType")
POLICY = {"allow": SAFE_ALLOW, "max_depth": 6, "require_signature": True}


class _ForbiddenClass:
    pass


def _envelope(payload_obj, key=KEY, tamper=False):
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
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_valid_envelope_loads_equivalent_object():
    """合法签名的安全对象应能原样等价加载。"""
    original = {
        "name": "cache",
        "items": [1, "two", True, None, 3.5],
        "nested": {"enabled": True},
    }

    loaded = safe_load(_envelope(original), POLICY, KEY)

    assert loaded == original


def test_wrong_signature_is_rejected():
    """签名被篡改时 verify_signature 返回否，总入口拒绝加载。"""
    blob = _envelope({"ok": True}, tamper=True)

    assert verify_signature(blob, KEY) is False
    with pytest.raises(ValueError):
        safe_load(blob, POLICY, KEY)


def test_dangerous_type_is_rejected():
    """即使签名合法，可执行类型也必须被类型白名单拒绝。"""
    blob = _envelope(_ForbiddenClass)

    with pytest.raises(ValueError):
        safe_load(blob, POLICY, KEY)


def test_depth_bomb_is_rejected():
    """超出深度上限的嵌套结构必须被拒绝。"""
    value = 1
    for _ in range(12):
        value = {"next": value}

    with pytest.raises(ValueError):
        safe_load(_envelope(value), POLICY, KEY)


def test_two_batches_match_individual_loads():
    """两个独立批次的结果应分别与单独加载一致。"""
    first_blob = _envelope({"id": "a", "values": [1, 2]})
    second_blob = _envelope({"id": "b", "values": [3]})

    first_batch = load_batch({"a": first_blob}, POLICY, KEY)
    second_batch = load_batch({"b": second_blob}, POLICY, KEY)

    assert first_batch["a"] == safe_load(first_blob, POLICY, KEY)
    assert second_batch["b"] == safe_load(second_blob, POLICY, KEY)
