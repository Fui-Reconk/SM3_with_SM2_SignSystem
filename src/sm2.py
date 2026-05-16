# -*- coding: utf-8 -*-
"""
SM2 椭圆曲线公钥密码算法 — 签名/验签
参考 GB/T 32918-2016 信息安全技术 SM2椭圆曲线公钥密码算法

实现了 SM2 推荐曲线上的：
  - 椭圆曲线点运算（点加、倍点、标量乘法）
  - 密钥对生成（私钥 32B，公钥 04||x||y 未压缩格式）
  - SM2 数字签名生成（SM3 哈希 + 随机数 k + (r,s) 签名值）
  - SM2 数字签名验证

SM2 推荐曲线参数 (y² = x³ + ax + b mod p)：
  p  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
  a  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
  b  = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
  n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
  Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
  Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
"""

import os
from src.sm3 import sm3_hash

# ═══════════════════════════════════════════════════════════
# SM2 推荐曲线参数（十六进制字符串 → 整数）
# ═══════════════════════════════════════════════════════════

# 素域 p
_SM2_P = int(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16
)
# 曲线参数 a = p - 3
_SM2_A = int(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16
)
# 曲线参数 b
_SM2_B = int(
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16
)
# 基点阶 n
_SM2_N = int(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16
)
# 基点 G 坐标
_SM2_GX = int(
    '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16
)
_SM2_GY = int(
    'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16
)

# 默认用户标识符 IDA（16 字节 ASCII），SM2 规范测试用值
_DEFAULT_ID = b'1234567812345678'


# ═══════════════════════════════════════════════════════════
# 有限域运算（模 p）
# ═══════════════════════════════════════════════════════════

def _mod_inv(a: int, m: int) -> int:
    """扩展欧几里得算法求模逆 a⁻¹ mod m"""
    if a == 0:
        raise ValueError("模逆不存在：输入为 0")
    return pow(a, -1, m)


# ═══════════════════════════════════════════════════════════
# 椭圆曲线点运算
# 曲线方程：y² ≡ x³ + ax + b (mod p)
# ═══════════════════════════════════════════════════════════

class ECPoint:
    """椭圆曲线点（仿射坐标），None 表示无穷远点 O"""

    __slots__ = ('x', 'y')

    def __init__(self, x: int, y: int):
        self.x = x % _SM2_P
        self.y = y % _SM2_P

    def __repr__(self):
        return f'ECPoint({hex(self.x)}, {hex(self.y)})'

    def __eq__(self, other):
        if other is None:
            return False
        return self.x == other.x and self.y == other.y

    def is_on_curve(self) -> bool:
        """验证点是否在 SM2 曲线上"""
        lhs = (self.y * self.y) % _SM2_P
        rhs = (pow(self.x, 3, _SM2_P) + _SM2_A * self.x + _SM2_B) % _SM2_P
        return lhs == rhs


def _point_add(p: ECPoint, q: ECPoint) -> ECPoint:
    """
    椭圆曲线点加 P + Q（仿射坐标）
    λ = (y₂ - y₁) / (x₂ - x₁) mod p   (P ≠ Q)
    x₃ = λ² - x₁ - x₂ mod p
    y₃ = λ(x₁ - x₃) - y₁ mod p
    """
    if p is None:
        return q
    if q is None:
        return p

    if p.x == q.x and p.y != q.y:
        return None  # P + (-P) = O

    if p.x == q.x and p.y == q.y:
        return _point_double(p)

    # P ≠ Q 的一般加法
    lam = ((q.y - p.y) * _mod_inv(q.x - p.x, _SM2_P)) % _SM2_P
    x3 = (lam * lam - p.x - q.x) % _SM2_P
    y3 = (lam * (p.x - x3) - p.y) % _SM2_P
    return ECPoint(x3, y3)


def _point_double(p: ECPoint) -> ECPoint:
    """
    椭圆曲线倍点 2P（仿射坐标）
    λ = (3x₁² + a) / (2y₁) mod p
    x₃ = λ² - 2x₁ mod p
    y₃ = λ(x₁ - x₃) - y₁ mod p
    """
    if p is None:
        return None

    lam = ((3 * p.x * p.x + _SM2_A) * _mod_inv(2 * p.y, _SM2_P)) % _SM2_P
    x3 = (lam * lam - 2 * p.x) % _SM2_P
    y3 = (lam * (p.x - x3) - p.y) % _SM2_P
    return ECPoint(x3, y3)


def _scalar_mult(k: int, p: ECPoint) -> ECPoint:
    """
    标量乘法 k·P（二进制展开法 / 双倍-加法）
    从高位向低位扫描，每步先倍点再条件加
    """
    if k == 0 or p is None:
        return None

    result = None  # 无穷远点
    addend = p

    while k > 0:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1

    return result


# ═══════════════════════════════════════════════════════════
# 预计算基点 G
# ═══════════════════════════════════════════════════════════

_G = ECPoint(_SM2_GX, _SM2_GY)


# ═══════════════════════════════════════════════════════════
# SM2 密钥对生成
# ═══════════════════════════════════════════════════════════

def generate_keypair() -> tuple:
    """
    生成 SM2 密钥对
    返回 (私钥_hex, 公钥_hex)
      私钥：32 字节随机数 d ∈ [1, n-1]，hex 64 字符
      公钥：未压缩格式 04||x||y，hex 130 字符
    """
    n = _SM2_N
    d = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1

    pub_point = _scalar_mult(d, _G)  # PA = dA·G

    # 未压缩格式：04 || x_32B || y_32B
    pub_bytes = b'\x04' + pub_point.x.to_bytes(32, 'big') + pub_point.y.to_bytes(32, 'big')

    return d.to_bytes(32, 'big').hex(), pub_bytes.hex()


# ═══════════════════════════════════════════════════════════
# ZA 计算（SM2 签名/验签的用户标识杂凑值）
# ═══════════════════════════════════════════════════════════

def _compute_za(pub_key_hex: str, ida: bytes = _DEFAULT_ID) -> bytes:
    """
    ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
    ENTLA = IDA 的位长度（2 字节大端）
    所有曲线参数使用 32 字节大端表示
    """
    entla = len(ida) * 8

    # 解析公钥中的 xA, yA（跳过 04 前缀）
    pub_bytes = bytes.fromhex(pub_key_hex)
    if pub_bytes[0] == 0x04:
        pub_bytes = pub_bytes[1:]
    xa = pub_bytes[:32]
    ya = pub_bytes[32:64]

    za_input = (
        entla.to_bytes(2, 'big')
        + ida
        + _SM2_A.to_bytes(32, 'big')
        + _SM2_B.to_bytes(32, 'big')
        + _SM2_GX.to_bytes(32, 'big')
        + _SM2_GY.to_bytes(32, 'big')
        + xa
        + ya
    )
    return sm3_hash(za_input)


# ═══════════════════════════════════════════════════════════
# SM2 数字签名生成
# ═══════════════════════════════════════════════════════════

def sm2_sign(message: bytes, priv_key_hex: str, pub_key_hex: str = None,
             ida: bytes = _DEFAULT_ID) -> str:
    """
    SM2 签名生成
      参数：
        message      : 待签名消息（原始字节）
        priv_key_hex : 私钥 hex（64 字符）
        pub_key_hex  : 对应公钥 hex（用于 ZA 计算，可选）
        ida          : 用户标识符
      返回：
        签名值 hex 字符串 = r(64hex) + s(64hex)，共 128 字符
      签名流程：
        1. 计算 ZA = SM3(ENTLA||IDA||a||b||xG||yG||xA||yA)
        2. 计算 e  = SM3(ZA || M)，转为整数
        3. 随机生成 k ∈ [1, n-1]
        4. 计算 (x1, y1) = k·G
        5. 计算 r = (e + x1) mod n，若 r=0 或 r+k=n 则重选 k
        6. 计算 s = (1+dA)⁻¹·(k - r·dA) mod n，若 s=0 则重选 k
        7. 输出 (r, s) 拼接
    """
    d = int(priv_key_hex, 16)
    n = _SM2_N

    # 计算 ZA 和杂凑值 e
    if pub_key_hex is None:
        pub = _scalar_mult(d, _G)
        pub_key_hex = '04' + pub.x.to_bytes(32, 'big').hex() + pub.y.to_bytes(32, 'big').hex()
    za = _compute_za(pub_key_hex, ida)
    e_bytes = sm3_hash(za + message)
    e = int.from_bytes(e_bytes, 'big')

    # 签名循环
    while True:
        # 生成随机数 k ∈ [1, n-1]
        k = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1

        # 计算 k·G
        kg = _scalar_mult(k, _G)
        x1 = kg.x

        # r = (e + x1) mod n
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue

        # s = (1+dA)⁻¹ · (k - r·dA) mod n
        d_inv = _mod_inv(1 + d, n)
        s = (d_inv * (k - r * d)) % n
        if s == 0:
            continue

        break

    # 输出签名 (r, s) 各 32 字节拼接 → 128 hex 字符
    return r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex()


# ═══════════════════════════════════════════════════════════
# SM2 数字签名验证
# ═══════════════════════════════════════════════════════════

def sm2_verify(message: bytes, signature_hex: str, pub_key_hex: str,
               ida: bytes = _DEFAULT_ID) -> bool:
    """
    SM2 签名验证
      参数：
        message       : 原始消息字节
        signature_hex : 签名值 hex（128 字符 = r||s）
        pub_key_hex   : 公钥 hex（130 字符，04||x||y）
        ida           : 用户标识符
      返回：
        True 验签成功 / False 验签失败
      验证流程：
        1. 从签名中恢复 r, s，检查 r,s ∈ [1, n-1]
        2. 计算 ZA 和 e = SM3(ZA || M')
        3. 计算 t = (r + s) mod n，若 t=0 则失败
        4. 计算 (x1, y1) = s·G + t·PA
        5. 计算 R = (e + x1) mod n
        6. 若 R == r 则验证成功
    """
    n = _SM2_N

    # 解析签名 (r, s)
    if len(signature_hex) != 128:
        return False
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    r = int.from_bytes(sig_bytes[:32], 'big')
    s = int.from_bytes(sig_bytes[32:64], 'big')

    # 检查 r, s ∈ [1, n-1]
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False

    # 解析公钥 PA
    pub_bytes = bytes.fromhex(pub_key_hex)
    if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
        return False
    pa_x = int.from_bytes(pub_bytes[1:33], 'big')
    pa_y = int.from_bytes(pub_bytes[33:65], 'big')
    pa = ECPoint(pa_x, pa_y)

    # 验证公钥在曲线上
    if not pa.is_on_curve():
        return False

    # 计算 ZA 和 e
    za = _compute_za(pub_key_hex, ida)
    e_bytes = sm3_hash(za + message)
    e = int.from_bytes(e_bytes, 'big')

    # t = (r + s) mod n
    t_val = (r + s) % n
    if t_val == 0:
        return False

    # (x1, y1) = s·G + t·PA
    sg = _scalar_mult(s, _G)       # s·G
    tpa = _scalar_mult(t_val, pa)  # t·PA
    result_point = _point_add(sg, tpa)
    if result_point is None:
        return False

    # R = (e + x1) mod n
    R = (e + result_point.x) % n

    # 验证 R == r
    return R == r


# ═══════════════════════════════════════════════════════════
# 辅助：从私钥推导公钥
# ═══════════════════════════════════════════════════════════

def privkey_to_pubkey(priv_key_hex: str) -> str:
    """从私钥 hex 推导公钥 hex（04||x||y）"""
    d = int(priv_key_hex, 16)
    pub = _scalar_mult(d, _G)
    pub_bytes = b'\x04' + pub.x.to_bytes(32, 'big') + pub.y.to_bytes(32, 'big')
    return pub_bytes.hex()
