"""安全反序列化加载器。

外层封装是 UTF-8 JSON，输入可以是 bytes 或 str，顶层必须且只能含有
version、encoding、payload、signature 四个字段：

- version 必须是整数 1；
- encoding 必须是字符串 pickle；
- payload 是 pickle 字节的 base64 ASCII 文本；
- signature 是 payload 的 base64 ASCII 文本的 HMAC-SHA256 小写十六进制。

策略 policy 是字典，包含 allow、max_depth、require_signature 三个字段。
allow 是类型名字符串的可迭代对象，按 type(value).__name__ 精确匹配；递归检查
dict 的键和值，以及 list 和 tuple 的元素，容器本身也必须被允许。max_depth
是深度上限，标量深度为 0，每进入一层 dict、list 或 tuple 深度加 1，恰好等于
上限可以接受，超过上限拒绝。require_signature 必须严格为 True。

本模块不提供任何容差：签名比较、深度边界和类型白名单都按 0 容差执行。除
verify_signature 用布尔值表示签名是否正确外，其余拒绝行为统一抛出 ValueError。
"""

import base64
import hashlib
import hmac
import json
import pickle

_FIELDS = frozenset({"version", "encoding", "payload", "signature"})
_EXECUTABLE_TYPE_NAMES = frozenset(
    {
        "function",
        "builtin_function_or_method",
        "method",
        "type",
        "code",
        "frame",
        "traceback",
        "module",
    }
)
_MAX_DEPTH_LIMIT = 32

# 仅这些类型被视为“标量”，可以按原值返回。
_SCALAR_TYPES = (
    type(None),
    bool,
    int,
    float,
    complex,
    str,
    bytes,
    bytearray,
)
_SCALAR_NAMES = frozenset(t.__name__ for t in _SCALAR_TYPES)


def _allow_items(allow):
    """把 allow 归一为 list[str]；非法时返回 None。

    只迭代一次，避免生成器被多次消费后变成空集。
    """
    if isinstance(allow, (str, bytes)):
        return None
    try:
        items = list(allow)
    except TypeError:
        return None
    if not all(type(item) is str for item in items):
        return None
    return items


def _snapshot_policy(policy):
    """把可迭代的 allow 物化为 list，避免生成器被多次遍历后耗尽。

    非法策略原样返回，交由 validate_policy 报告。
    """
    if type(policy) is not dict or "allow" not in policy:
        return policy
    items = _allow_items(policy["allow"])
    if items is None:
        return policy
    snapshot = dict(policy)
    snapshot["allow"] = items
    return snapshot


def _normalize_allow(allow) -> frozenset:
    items = _allow_items(allow)
    if items is None:
        raise ValueError("allow 必须是类型名字符串的可迭代对象")
    return frozenset(items)


def _reject_constant(token):
    raise ValueError(f"非法 JSON 常量: {token}")


def _object_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"重复字段: {key}")
        obj[key] = value
    return obj


def _decode_envelope(blob):
    """严格解码外层封装，返回 (规范化字典, payload 的 base64 原始字节)。

    内部的 payload 是已解码的 bytes；原始字节保留给签名校验使用，因为签名
    覆盖的是 payload 字段里 base64 ASCII 文本本身。
    """
    if isinstance(blob, bytes):
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("封装不是合法的 UTF-8 字节") from exc
    elif isinstance(blob, str):
        text = blob
    else:
        raise ValueError("封装必须是 UTF-8 JSON 的 bytes 或 str")

    try:
        fields = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("封装不是合法的 JSON") from exc

    if type(fields) is not dict:
        raise ValueError("封装顶层必须是一个 JSON 对象")
    if set(fields) != _FIELDS:
        raise ValueError("封装顶层字段必须且只能是 version、encoding、payload、signature")

    version = fields["version"]
    if type(version) is not int or version != 1:
        raise ValueError("version 必须为整数 1")

    encoding = fields["encoding"]
    if type(encoding) is not str or encoding != "pickle":
        raise ValueError("encoding 必须为字符串 pickle")

    payload = fields["payload"]
    if type(payload) is not str:
        raise ValueError("payload 必须是 base64 ASCII 字符串")
    try:
        payload_b64 = payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("payload 必须是 base64 ASCII 字符串") from exc
    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise ValueError("payload 不是合法的 base64") from exc

    signature = fields["signature"]
    if (
        type(signature) is not str
        or len(signature) != 64
        or any(ch not in "0123456789abcdef" for ch in signature)
    ):
        raise ValueError("signature 必须是 64 位小写十六进制字符串")

    decoded = {
        "version": 1,
        "encoding": "pickle",
        "payload": payload_bytes,
        "signature": signature,
    }
    return decoded, payload_b64


def decode_blob(blob) -> dict:
    """严格解码外层封装，不执行 pickle。

    接受 UTF-8 JSON 的 bytes 或 str，返回只含 version、encoding、payload、
    signature 的字典，其中 payload 已从 base64 解码为 bytes，signature 保持
    小写十六进制字符串。顶层字段必须与上述四个字段完全一致，多一个、少一个、
    重复字段、未知 version 或 encoding、非法 base64、签名不是 64 位小写十六
    进制，均视为格式非法并抛出 ValueError。此函数必须使用严格模式，不得静默
    忽略任何多余字段。
    """
    decoded, _ = _decode_envelope(blob)
    return decoded


def verify_signature(blob, key) -> bool:
    """校验封装签名，比较容差为 0。

    key 必须是 bytes。签名消息是 payload 字段中 base64 ASCII 文本的原始字节，
    算法固定为 HMAC-SHA256，输出小写十六进制。必须调用
    hmac.compare_digest 做恒定时间比较，禁止使用普通等号。签名正确返回 True，
    签名错误返回 False；封装格式非法时抛出 ValueError。
    """
    if type(key) is not bytes:
        raise ValueError("key 必须是 bytes")

    decoded, payload_b64 = _decode_envelope(blob)
    expected = hmac.new(key, payload_b64, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, decoded["signature"])


def type_allowed(value, allow) -> bool:
    """判断值是否完全落在类型白名单内，容差为 0。

    allow 是类型名字符串的可迭代对象，按 type(value).__name__ 精确匹配。标量
    直接判断；dict 要求 dict 本身、每个键和每个值都允许；list 与 tuple 要求
    容器本身和每个元素都允许。只要任意一层出现白名单外类型就返回 False，不能
    只检查最外层。可执行类型默认不在任何安全白名单内。
    """
    allowed = _normalize_allow(allow)
    if type(value) in _SCALAR_TYPES:
        return type(value).__name__ in allowed
    if type(value) is dict:
        if "dict" not in allowed:
            return False
        return all(
            type_allowed(k, allowed) and type_allowed(v, allowed)
            for k, v in value.items()
        )
    if type(value) is list:
        if "list" not in allowed:
            return False
        return all(type_allowed(item, allowed) for item in value)
    if type(value) is tuple:
        if "tuple" not in allowed:
            return False
        return all(type_allowed(item, allowed) for item in value)
    # 任何其它类型（含可执行类型、自定义类实例等）一律不在白名单内。
    return False


def depth_ok(value, limit) -> bool:
    """判断嵌套深度是否不超过 limit，边界容差为 0。

    标量深度为 0；dict、list、tuple 每进入一层深度加 1，dict 的键和值都参与
    检测。深度恰好等于 limit 返回 True，深度大于 limit 返回 False。limit 必须
    是非负整数，否则抛出 ValueError。必须同时统计字典和列表嵌套，不能只统计
    列表层数。
    """
    if type(limit) is not int or limit < 0:
        raise ValueError("limit 必须是非负整数")

    def _within(node, remaining):
        """remaining 为还能继续进入的容器层数。"""
        if type(node) is dict:
            if remaining <= 0:
                return False
            contents = list(node.keys()) + list(node.values())
        elif type(node) in (list, tuple):
            if remaining <= 0:
                return False
            contents = list(node)
        else:
            return True
        return all(_within(child, remaining - 1) for child in contents)

    return _within(value, limit)


def safe_load(blob, policy, key) -> object:
    """安全加载总入口：先验签，再按白名单重建对象。

    顺序固定为：先用 validate_policy 检查策略，问题列表非空则拒绝；再用
    decode_blob 严格解码外层封装；然后调用 verify_signature，签名不通过立即
    抛出 ValueError；只有验签通过后才允许对 payload 调用 pickle.loads。得到
    对象后依次执行 depth_ok 与 type_allowed，最后由 rebuild 构造新对象。任何
    环节失败都抛出 ValueError，且验签失败时绝不能触发任何 pickle 反序列化
    副作用。
    """
    policy = _snapshot_policy(policy)
    issues = validate_policy(policy)
    if issues:
        raise ValueError(f"策略非法: {issues}")
    if type(key) is not bytes:
        raise ValueError("key 必须是 bytes")

    decoded, payload_b64 = _decode_envelope(blob)

    expected = hmac.new(key, payload_b64, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, decoded["signature"]):
        raise ValueError("签名校验失败")

    try:
        obj = pickle.loads(decoded["payload"])
    except Exception as exc:
        raise ValueError("payload 反序列化失败") from exc

    if not depth_ok(obj, policy["max_depth"]):
        raise ValueError("嵌套深度超过上限")
    if not type_allowed(obj, policy["allow"]):
        raise ValueError("类型不在白名单内")
    return rebuild(obj, policy["allow"])


def rebuild(value, allow) -> object:
    """按类型白名单递归重建对象，未知类型直接拒绝。

    allow 是类型名字符串的可迭代对象。dict 重建为新 dict，list 重建为新 list，
    tuple 重建为新 tuple，标量按原值返回；容器本身也必须在白名单内。遇到任何
    白名单外类型必须抛出 ValueError，绝不能把原值或危险对象原样返回。重建过程
    必须递归到每一层，不能只处理最外层。
    """
    allowed = _normalize_allow(allow)
    name = type(value).__name__

    if type(value) is dict:
        if "dict" not in allowed:
            raise ValueError("dict 不在类型白名单内")
        return {rebuild(k, allowed): rebuild(v, allowed) for k, v in value.items()}
    if type(value) is list:
        if "list" not in allowed:
            raise ValueError("list 不在类型白名单内")
        return [rebuild(item, allowed) for item in value]
    if type(value) is tuple:
        if "tuple" not in allowed:
            raise ValueError("tuple 不在类型白名单内")
        return tuple(rebuild(item, allowed) for item in value)
    if name in _SCALAR_NAMES and name in allowed:
        return value
    raise ValueError(f"未知或不允许的类型: {name}")


def validate_policy(policy) -> list[str]:
    """返回策略问题代码列表，合法策略返回空列表。

    必须识别以下问题，并使用固定代码：
    executable_type 表示 allow 含可执行类型名（function、
    builtin_function_or_method、method、type、code、frame、traceback、module）；
    depth_limit_too_large 表示 max_depth 大于 32；
    depth_limit_invalid 表示 max_depth 不是非负整数；
    signature_not_required 表示 require_signature 不严格等于 True；
    invalid_allowlist 表示 allow 缺失或不是类型名字符串的可迭代对象；
    invalid_policy 表示 policy 不是字典。必须检查是否强制验签，不能因为
    require_signature 缺失就当成已启用。
    """
    if type(policy) is not dict:
        return ["invalid_policy"]

    issues = []

    if "allow" not in policy:
        issues.append("invalid_allowlist")
    else:
        allow = policy["allow"]
        items = _allow_items(allow)
        if items is None:
            issues.append("invalid_allowlist")
        elif set(items) & _EXECUTABLE_TYPE_NAMES:
            issues.append("executable_type")

    if "max_depth" not in policy:
        issues.append("depth_limit_invalid")
    else:
        max_depth = policy["max_depth"]
        if type(max_depth) is not int or max_depth < 0:
            issues.append("depth_limit_invalid")
        elif max_depth > _MAX_DEPTH_LIMIT:
            issues.append("depth_limit_too_large")

    if policy.get("require_signature") is not True:
        issues.append("signature_not_required")

    return issues


def load_batch(blobs, policy, key) -> dict:
    """批量加载，各输入完全独立。

    blobs 是标签到封装的映射。先验证一次 policy；随后对每个输入单独调用
    safe_load，禁止复用其它输入的验签结果、异常或中间状态。返回与输入标签
    对应的字典：成功项的值是加载出的对象，失败项的值是该输入捕获到的异常
    实例。单个输入失败不得影响其它输入。
    """
    policy = _snapshot_policy(policy)
    issues = validate_policy(policy)
    if issues:
        raise ValueError(f"策略非法: {issues}")

    results = {}
    for label, blob in blobs.items():
        try:
            results[label] = safe_load(blob, policy, key)
        except Exception as exc:
            results[label] = exc
    return results
