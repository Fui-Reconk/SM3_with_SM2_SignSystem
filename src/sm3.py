# -*- coding: utf-8 -*-
"""
SM3 密码杂凑算法 — 纯Python实现
参考 GB/T 32905-2016 信息安全技术 SM3密码杂凑算法

SM3 输出 256-bit 杂凑值，结构：
  1. 消息填充（附加 '1'、补 '0'、附加 64-bit 长度）
  2. 消息扩展（W[0..67] 和 W'[0..63]）
  3. 压缩函数 CF（64 轮迭代，每轮使用 FF/GG 布尔函数和置换 P0/P1）
  4. 输出 256-bit 杂凑值
"""

# --- 初始值 IV（8 个 32-bit 字） ---
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]


def _rotl(x: int, n: int) -> int:
    """32-bit 循环左移"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _t(j: int) -> int:
    """压缩函数常量 T_j"""
    if 0 <= j <= 15:
        return 0x79CC4519
    else:
        return 0x7A879D8A


def _ff(x: int, y: int, z: int, j: int) -> int:
    """布尔函数 FF_j"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)


def _gg(x: int, y: int, z: int, j: int) -> int:
    """布尔函数 GG_j"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (~x & z)


def _p0(x: int) -> int:
    """置换函数 P0: X ⊕ (X<<<9) ⊕ (X<<<17)"""
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    """置换函数 P1: X ⊕ (X<<<15) ⊕ (X<<<23)"""
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _pad(msg: bytes) -> bytes:
    """
    消息填充：
      m' = m || 1 || 0...0 || len(m)_64
      使得填充后总长度 ≡ 0 (mod 512)
    """
    bit_len = len(msg) * 8
    msg += b'\x80'
    # 填充至长度 ≡ 56 (mod 64) 即 ≡ 448 (mod 512) bits
    while (len(msg) % 64) != 56:
        msg += b'\x00'
    msg += bit_len.to_bytes(8, 'big')
    return msg


def _message_expansion(block: bytes):
    """
    消息扩展：将 512-bit 消息块扩展为 132 个 32-bit 字
      W[0..15] ← 消息分块
      W[16..67] ← P1(W[j-16] ⊕ W[j-9] ⊕ (W[j-3]<<<15)) ⊕ (W[j-13]<<<7) ⊕ W[j-6]
      W'[j] ← W[j] ⊕ W[j+4]   (j = 0..63)
    """
    # 将 64 字节解析为 16 个 32-bit 大端字
    W = [0] * 68
    for i in range(16):
        W[i] = int.from_bytes(block[4 * i:4 * i + 4], 'big')

    for j in range(16, 68):
        W[j] = (
            _p1(W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15))
            ^ _rotl(W[j - 13], 7)
            ^ W[j - 6]
        ) & 0xFFFFFFFF

    W1 = [0] * 64
    for j in range(64):
        W1[j] = W[j] ^ W[j + 4]

    return W, W1


def _cf(v: list, block: bytes) -> list:
    """
    压缩函数 CF(V, B)：
      将 256-bit V 与 512-bit 消息块 B 压缩，输出新的 256-bit 值
      主循环 64 轮，使用 A/B/C/D/E/F/G/H 8 个 32-bit 寄存器
    """
    W, W1 = _message_expansion(block)

    A, B, C, D, E, F, G, H = v
    SS1 = SS2 = TT1 = TT2 = 0

    for j in range(64):
        # SS1 计算及寄存器移位
        SS1 = _rotl((_rotl(A, 12) + E + _rotl(_t(j), j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_ff(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF
        TT2 = (_gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _p0(TT2)

    # 异或合并
    return [
        A ^ v[0], B ^ v[1], C ^ v[2], D ^ v[3],
        E ^ v[4], F ^ v[5], G ^ v[6], H ^ v[7],
    ]


def sm3_hash(message: bytes) -> bytes:
    """
    SM3 哈希主函数
      输入：任意长度字节串
      输出：32 字节（256-bit）杂凑值
    """
    padded = _pad(message)
    V = list(IV)

    for i in range(0, len(padded), 64):
        V = _cf(V, padded[i:i + 64])

    return b''.join(v.to_bytes(4, 'big') for v in V)


def sm3_hash_hex(message: bytes) -> str:
    """SM3 哈希，返回十六进制字符串"""
    return sm3_hash(message).hex()
