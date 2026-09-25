# -*- coding: utf-8 -*-
"""
怪物猎人：荒野 (Monster Hunter Wilds) 存档核心库
- Mandarin 加密/解密 (SplitMix64 + AES-128-OFB + Elgamal 认证块 + CityHash64 校验 + RSA 尾)
- DEFLATE 压缩层
- RSZ 类结构解析 (字段 hash = murmur3_32(字段名, 0xFFFFFFFF))
仅用于个人存档修改，风险自负。
"""
import struct
import zlib

MASK64 = (1 << 64) - 1
MASK32 = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# SplitMix64 (z 链: state <- next_int(state) 的返回值 z)
# ---------------------------------------------------------------------------
SM_ADD = 0x9E3779B97F4A7C15
SM_MUL1 = 0xBF58476D1CE4E5B9
SM_MUL2 = 0x94D049BB133111EB


def sm64(state: int) -> int:
    """返回 z；调用方负责 state = z（z 链）"""
    state = (state + SM_ADD) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * SM_MUL1) & MASK64
    z = ((z ^ (z >> 27)) * SM_MUL2) & MASK64
    return z ^ (z >> 31)


# ---------------------------------------------------------------------------
# murmur3_32 (MurmurHash3 x86_32)
# ---------------------------------------------------------------------------
def murmur3_32(data: bytes, seed: int = 0xFFFFFFFF) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & MASK32
    n = len(data) & ~3
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], 'little')
        k = (k * c1) & MASK32
        k = ((k << 15) | (k >> 17)) & MASK32
        k = (k * c2) & MASK32
        h ^= k
        h = ((h << 13) | (h >> 19)) & MASK32
        h = (h * 5 + 0xE6546B64) & MASK32
    tail = data[n:]
    if tail:
        k = 0
        if len(tail) >= 3:
            k ^= tail[2] << 16
        if len(tail) >= 2:
            k ^= tail[1] << 8
        k ^= tail[0]
        k = (k * c1) & MASK32
        k = ((k << 15) | (k >> 17)) & MASK32
        k = (k * c2) & MASK32
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & MASK32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & MASK32
    h ^= h >> 16
    return h


# ---------------------------------------------------------------------------
# CityHash64 (Google CityHash, 按 cityhasher-rs 移植)
# ---------------------------------------------------------------------------
K0 = 0xC3A5C85C97CB3127
K1 = 0xB492B66FBE98F273
K2 = 0x9AE16A3B2F90404F


def _rot64(val, shift):
    return val if shift == 0 else ((val >> shift) | (val << (64 - shift))) & MASK64


def _f64(b, i):
    return struct.unpack_from('<Q', b, i)[0]


def _f32(b, i):
    return struct.unpack_from('<I', b, i)[0]


def _shift_mix(val):
    return (val ^ (val >> 47)) & MASK64


def _hash_len16(u, v, mul):
    a = ((u ^ v) * mul) & MASK64
    a ^= a >> 47
    b = ((v ^ a) * mul) & MASK64
    b ^= b >> 47
    return (b * mul) & MASK64


def _hash_len16_uv(u, v):
    return _hash_len16(u, v, 0x9DDFEA08EB382D69)


def _weak32(w, x, y, z, a, b):
    """weak_hash_len_32_with_seeds(w, x, y, z, a, b) — 按 cityhasher-rs 逐行移植"""
    a = (a + w) & MASK64
    b = _rot64((b + a + z) & MASK64, 21)
    c = a
    a = (a + x) & MASK64
    a = (a + y) & MASK64
    b = (b + _rot64(a, 44)) & MASK64
    return (a + z) & MASK64, (b + c) & MASK64


def cityhash64(data: bytes) -> int:
    length = len(data)

    def fetch64(i):
        return struct.unpack_from('<Q', data, i)[0]

    def fetch32(i):
        return struct.unpack_from('<I', data, i)[0]

    if length <= 16:
        # hash64_len_0_to_16
        if length >= 8:
            mul = (K2 + length * 2) & MASK64
            a = (fetch64(0) + K2) & MASK64
            b = fetch64(length - 8)
            c = (_rot64(b, 37) * mul + a) & MASK64
            d = ((_rot64(a, 25) + b) * mul) & MASK64
            return _hash_len16(c, d, mul)
        if length >= 4:
            mul = (K2 + length * 2) & MASK64
            a = fetch32(0)
            return _hash_len16((length + (a << 3)) & MASK64,
                               fetch32(length - 4), mul)
        if length > 0:
            a = data[0]
            b = data[length >> 1]
            c = data[length - 1]
            y = a + (b << 8)
            z = (length + (c << 2)) & MASK32
            return (_shift_mix((y * K2) ^ ((z * K0) & MASK64)) * K2) & MASK64
        return K2
    if length <= 32:
        # hash64_len_17_to_32
        mul = (K2 + length * 2) & MASK64
        a = (fetch64(0) * K1) & MASK64
        b = fetch64(8)
        c = (fetch64(length - 8) * mul) & MASK64
        d = (fetch64(length - 16) * K2) & MASK64
        return _hash_len16(
            (_rot64(a + b, 43) + _rot64(c, 30) + d) & MASK64,
            (a + _rot64((b + K2) & MASK64, 18) + c) & MASK64,
            mul)
    if length <= 64:
        # hash64_len_33_to_64
        mul = (K2 + length * 2) & MASK64
        a = (fetch64(0) * K2) & MASK64
        b = fetch64(8)
        c = fetch64(length - 24)
        d = fetch64(length - 32)
        e = (fetch64(16) * K2) & MASK64
        f = (fetch64(24) * 9) & MASK64
        g = fetch64(length - 8)
        h = (fetch64(length - 16) * mul) & MASK64
        u = (_rot64(a + g, 43) + (_rot64(b, 30) + c) * 9) & MASK64
        v = (((a + g) ^ d) + f + 1) & MASK64
        w = (_byteswap64(((u + v) * mul) & MASK64) + h) & MASK64
        x = (_rot64(e + f, 42) + c) & MASK64
        y = ((_byteswap64(((v + w) * mul) & MASK64) + g) * mul) & MASK64
        z = (e + f + c) & MASK64
        a2 = (_byteswap64(((x + z) * mul + y) & MASK64) + b) & MASK64
        b2 = _shift_mix(((z + a2) * mul + d + h) & MASK64) * mul & MASK64
        return (b2 + x) & MASK64

    # length > 64
    x = fetch64(length - 40)
    y = (fetch64(length - 16) + fetch64(length - 56)) & MASK64
    z = _hash_len16_uv((fetch64(length - 48) + length) & MASK64,
                       fetch64(length - 24))
    v = _weak32(fetch64(length - 64), fetch64(length - 56),
                fetch64(length - 48), fetch64(length - 40), length, z)
    w = _weak32(fetch64(length - 32), fetch64(length - 24),
                fetch64(length - 16), fetch64(length - 8),
                (y + K1) & MASK64, x)
    x = (x * K1 + fetch64(0)) & MASK64

    offset = 0
    # 按 64 字节块迭代，直到不含最后 64 字节的部分
    while offset + 64 <= length - 1:
        c8 = fetch64(offset + 8)
        c48 = fetch64(offset + 48)
        c40 = fetch64(offset + 40)
        c16 = fetch64(offset + 16)
        x = _rot64((x + y + v[0] + c8) & MASK64, 37) * K1 & MASK64
        y = _rot64((y + v[1] + c48) & MASK64, 42) * K1 & MASK64
        x ^= w[1]
        y = (y + v[0] + c40) & MASK64
        z = _rot64((z + w[0]) & MASK64, 33) * K1 & MASK64
        v = _weak32(fetch64(offset), fetch64(offset + 8),
                    fetch64(offset + 16), fetch64(offset + 24),
                    (v[1] * K1) & MASK64, (x + w[0]) & MASK64)
        w = _weak32(fetch64(offset + 32), fetch64(offset + 40),
                    fetch64(offset + 48), fetch64(offset + 56),
                    (z + w[1]) & MASK64, (y + c16) & MASK64)
        z, x = x, z
        offset += 64

    return _hash_len16_uv(
        (_hash_len16_uv(v[0], w[0]) + _shift_mix(y) * K1 + z) & MASK64,
        (_hash_len16_uv(v[1], w[1]) + x) & MASK64)


def _byteswap64(v):
    return int.from_bytes(v.to_bytes(8, 'little'), 'big')


# ---------------------------------------------------------------------------
# AES-128-OFB (优先 cryptography 库，回退纯 Python)
# ---------------------------------------------------------------------------
def _aes_ofb_native(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(key), modes.OFB(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes128_ofb(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) == 0:
        return data
    try:
        return _aes_ofb_native(key, iv, data)
    except ImportError:
        return _aes_ofb_pure(key, iv, data)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _aes_ofb_pure(key, iv, data):
    """纯 Python AES-128 OFB（无依赖回退方案，较慢）"""
    sbox = _AES_SBOX
    def expand(k):
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        w = [list(k[i * 4:i * 4 + 4]) for i in range(4)]
        for i in range(4, 44):
            t = list(w[i - 1])
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [sbox[b] for b in t]
                t[0] ^= rcon[i // 4 - 1]
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        return w

    def encrypt_block(block, w):
        state = [block[r + 4 * c] for c in range(4) for r in range(4)]
        def addrk(rnd):
            for c in range(4):
                for r in range(4):
                    state[r + 4 * c] ^= w[rnd * 4 + c][r]
        addrk(0)
        for rnd in range(1, 11):
            state[:] = [sbox[b] for b in state]
            state = _shift_rows(state)
            if rnd != 10:
                state = _mix_columns(state)
            addrk(rnd)
        return bytes(state)

    w = expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        ks = encrypt_block(prev, w)
        prev = ks
        out += _xor(data[i:i + 16], ks)
    return bytes(out)


def _shift_rows(s):
    return [s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11]]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mix_columns(s):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        out.append(_xtime(col[0]) ^ (_xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3])
        out.append(col[0] ^ _xtime(col[1]) ^ (_xtime(col[2]) ^ col[2]) ^ col[3])
        out.append(col[0] ^ col[1] ^ _xtime(col[2]) ^ (_xtime(col[3]) ^ col[3]))
        out.append((_xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ _xtime(col[3]))
    return out


_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


# ---------------------------------------------------------------------------
# Mandarin 加密 (MH Wilds)
# ---------------------------------------------------------------------------
WILDS_SEED_RSA = 0xBFACF76C3F96       # seed_for_rsa_rand
WILDS_SEED_ENC = 0x7A36955255266CED   # seed_for_enc_rand

ELGAMAL_P = int.from_bytes(bytes.fromhex(
    "f33b6fb972a0b72515e45c391829e182ad8a9bdc0a64d3444d79c810ab863717"), 'little')
ELGAMAL_Q = int.from_bytes(bytes.fromhex(
    "f99db75c39d0db920a72ae1c8c9470c156c54d6e05b269a2a63c648855c39b0b"), 'little')
ELGAMAL_R = int.from_bytes(bytes.fromhex(
    "e66f544afcce68c5ef07b9a07b277585344a1db61376e831f73b9fbd5f44f715"), 'little')

RSA_N = int.from_bytes(bytes.fromhex(
    "4fa448364f5b3507e945075cc21994bdedef96962c74d53159d50a5c62ed5086"
    "4885ddfe79705dfad0b638220ca2299fccae152164590cc89d33698452a8f6416"
    "107a6952f126bb21ee3e332d2285db728c09bfa8cbd4c3b13b358b9838dea7cf3"
    "9dc12e37066a09cf7809a0d0ea06c3bbaa14776400f403f863ed83b5bdd3c2"), 'little')

BLOCK_UNIT = 0x4000
AUTH_SIZE = 0x210


class ChecksumError(Exception):
    pass


def _mandarin_block_sizes(decrypted_len: int):
    """返回 (sizes, state_p_after)。sizes[i] ∈ 1..8（×0x4000 字节）"""
    n_pot = ((decrypted_len & 0x3FFF) != 0) + (decrypted_len >> 14)
    sizes = []
    state = WILDS_SEED_ENC
    for _ in range(n_pot):
        sizes.append((state & 7) + 1)
        state = sm64(state)
    return sizes, state


def mandarin_decrypt(encrypted: bytes, decrypted_len: int, key: int) -> bytes:
    """key = SteamID64。返回明文（长度 decrypted_len）"""
    sizes, state = _mandarin_block_sizes(decrypted_len)
    # 数实际块数（保持与 Rust 相同的推进逻辑）
    leftover = decrypted_len
    num_real = 0
    for s in sizes:
        num_real += 1
        if leftover <= s * BLOCK_UNIT:
            break
        leftover -= s * BLOCK_UNIT

    state = (state + (~key & MASK64)) & MASK64
    out = bytearray(decrypted_len)
    remaining = decrypted_len
    dec_start = 0
    enc_start = 0

    for i in range(num_real):
        block_size = sizes[i] * BLOCK_UNIT
        enc_read = block_size + AUTH_SIZE
        buf = bytearray(encrypted[enc_start:enc_start + enc_read])
        if len(buf) < enc_read:
            raise ChecksumError(f"块 {i} 越界: 需要 {enc_read}, 剩余 {len(buf)}")

        # 生成 key / iv
        k16 = bytearray(16)
        iv16 = bytearray(16)
        for j in range(16):
            state = sm64(state)
            k16[j] = state & 0xFF
            iv16[j] = (state >> 8) & 0xFF

        # 认证头 0x210 字节与 PRNG 掩码异或
        for j in range(AUTH_SIZE):
            state = sm64(state)
            buf[j] ^= state & 0xFF

        target_checksum = struct.unpack_from('<Q', buf, 0x200)[0]

        plain = aes128_ofb(bytes(k16), bytes(iv16), bytes(buf[AUTH_SIZE:]))
        n_copy = min(block_size, remaining)
        checksum = cityhash64(plain[:n_copy])
        if checksum != target_checksum:
            raise ChecksumError(
                f"块 {i}: CityHash64 校验失败 (目标 {target_checksum:#x}, "
                f"实际 {checksum:#x}) —— SteamID 或密钥错误")
        out[dec_start:dec_start + n_copy] = plain[:n_copy]
        remaining = (remaining - block_size) & MASK64  # 与 Rust wrapping 行为一致
        dec_start += n_copy
        enc_start += enc_read

    return bytes(out)


def mandarin_encrypt(data: bytes, key: int) -> bytes:
    sizes, state = _mandarin_block_sizes(len(data))
    leftover = len(data)
    num_real = 0
    for s in sizes:
        num_real += 1
        if leftover <= s * BLOCK_UNIT:
            break
        leftover -= s * BLOCK_UNIT

    state = (state + (~key & MASK64)) & MASK64
    out = bytearray()
    remaining = len(data)
    dec_start = 0

    # Elgamal 认证
    u = (~key & MASK64) % ELGAMAL_Q
    s_elg = pow(ELGAMAL_R, u, ELGAMAL_P)
    x0_pre = pow(ELGAMAL_R, 20, ELGAMAL_P)
    x1_pre = pow(s_elg, 20, ELGAMAL_P)

    def elg_encrypt8(pt8: bytes):
        ct = x1_pre * int.from_bytes(pt8, 'little')
        return (x0_pre.to_bytes(64, 'little'), ct.to_bytes(64, 'little'))

    for i in range(num_real):
        block_size = sizes[i] * BLOCK_UNIT
        n_copy = min(block_size, remaining)

        k16 = bytearray(16)
        iv16 = bytearray(16)
        for j in range(16):
            state = sm64(state)
            k16[j] = state & 0xFF
            iv16[j] = (state >> 8) & 0xFF

        plain = data[dec_start:dec_start + n_copy]
        cipher = aes128_ofb(bytes(k16), bytes(iv16),
                            plain + b'\x00' * (block_size - n_copy))

        key_iv = bytes(k16) + bytes(iv16)
        head = bytearray(AUTH_SIZE)
        for c in range(4):
            x0b, ctb = elg_encrypt8(key_iv[c * 8:c * 8 + 8])
            head[c * 128:c * 128 + 64] = x0b
            head[c * 128 + 64:(c + 1) * 128] = ctb
        struct.pack_into('<Q', head, 0x200, cityhash64(plain))

        for j in range(AUTH_SIZE):
            state = sm64(state)
            head[j] ^= state & 0xFF

        out += head + cipher
        remaining -= n_copy
        dec_start += n_copy

    # RSA 尾: rands[0..8] = ~key LE; 其余 = (SEED_RSA + (i+1)*ADD) 低字节
    rands = bytearray(32)
    sa = WILDS_SEED_RSA
    for i in range(32):
        sa = (sa + SM_ADD) & MASK64
        rands[i] = sa & 0xFF
    rands[0:8] = struct.pack('<Q', ~key & MASK64)
    enc_key = pow(int.from_bytes(bytes(rands), 'little'), 65537, RSA_N)
    out += enc_key.to_bytes(0x80, 'little')
    return bytes(out)


# ---------------------------------------------------------------------------
# 存档文件封装 (DSSS)
# ---------------------------------------------------------------------------
FLAG_DEFLATE = 0x8
FLAG_MANDARIN = 0x10


def unpack_save(file_bytes: bytes, steamid64: int):
    """返回解密+解压后的 RSZ 明文缓冲区"""
    if file_bytes[:4] != b'DSSS':
        raise ValueError("不是 DSSS 存档文件")
    version, flags = struct.unpack_from('<II', file_bytes, 4)
    if version != 2:
        raise ValueError(f"不支持的存档版本 {version}")

    stored_hash = struct.unpack_from('<I', file_bytes, len(file_bytes) - 4)[0]
    calc_hash = murmur3_32(file_bytes[:-4], 0xFFFFFFFF)
    if stored_hash != calc_hash:
        raise ValueError("文件级 murmur3 校验失败（文件损坏?）")

    if flags & FLAG_MANDARIN:
        offset = 16  # 12 头 + 对齐 16
        decrypted_len = struct.unpack_from('<Q', file_bytes, len(file_bytes) - 12)[0]
        enc = file_bytes[offset:len(file_bytes) - 4]
        payload = mandarin_decrypt(enc, decrypted_len, steamid64)
    else:
        raise ValueError(f"不支持的 flags: {flags:#x}（本工具仅支持 Mandarin 加密的存档）")

    if flags & FLAG_DEFLATE:
        (comp_size_p10, unk1, comp_size, decomp_size) = struct.unpack_from('<QIIQ', payload, 0)
        compressed = payload[24:24 + comp_size]
        plain = zlib.decompress(compressed, -15)
        if len(plain) != decomp_size:
            raise ValueError("解压尺寸不匹配")
        return plain
    return payload


def pack_save(plain: bytes, steamid64: int) -> bytes:
    """RSZ 明文 → 完整加密存档文件"""
    comp = zlib.compressobj(5, zlib.DEFLATED, -15)
    compressed = comp.compress(plain) + comp.flush()
    payload = struct.pack('<QIIQ', len(compressed) + 0x10, 1,
                          len(compressed), len(plain)) + compressed

    head = b'DSSS' + struct.pack('<II', 2, FLAG_DEFLATE | FLAG_MANDARIN) + b'\x00' * 4
    enc = mandarin_encrypt(payload, steamid64)
    body = head + enc + struct.pack('<Q', len(payload))

    pad = (-len(body)) % 4
    body += b'\x00' * pad
    return body + struct.pack('<I', murmur3_32(body, 0xFFFFFFFF))


# ---------------------------------------------------------------------------
# RSZ 结构解析（只读 + 偏移记录；修改时按偏移 patch，绝不重建结构）
# ---------------------------------------------------------------------------
FT_ARRAY = -1
FT_ENUM, FT_BOOL, FT_S8, FT_U8, FT_S16, FT_U16, FT_S32, FT_U32 = 1, 2, 3, 4, 5, 6, 7, 8
FT_S64, FT_U64, FT_F32, FT_F64, FT_C8, FT_C16, FT_STRING, FT_STRUCT, FT_CLASS = \
    9, 10, 11, 12, 13, 14, 15, 16, 17

FT_SIZE = {FT_BOOL: 1, FT_S8: 1, FT_U8: 1, FT_C8: 1,
           FT_S16: 2, FT_U16: 2, FT_C16: 2,
           FT_S32: 4, FT_U32: 4, FT_F32: 4,
           FT_S64: 8, FT_U64: 8, FT_F64: 8}


class Reader:
    __slots__ = ('buf', 'pos')

    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def align(self, a):
        self.pos += (-self.pos) % a if self.pos % a else 0

    def u8(self):
        v = self.buf[self.pos]; self.pos += 1; return v

    def u16(self):
        v = struct.unpack_from('<H', self.buf, self.pos)[0]; self.pos += 2; return v

    def u32(self):
        v = struct.unpack_from('<I', self.buf, self.pos)[0]; self.pos += 4; return v

    def i32(self):
        v = struct.unpack_from('<i', self.buf, self.pos)[0]; self.pos += 4; return v


class FieldRec:
    """扁平字段记录: 数字/枚举字段的 (类hash, 字段hash, 值字节偏移, 类型, 值)"""
    __slots__ = ('path', 'class_hash', 'field_hash', 'offset', 'ftype', 'value')

    def __init__(self, path, class_hash, field_hash, offset, ftype, value):
        self.path = path
        self.class_hash = class_hash
        self.field_hash = field_hash
        self.offset = offset
        self.ftype = ftype
        self.value = value


def read_class(r: Reader, fields_out: list, path: str):
    """递归解析 Class；数字字段记入 fields_out
    语义与 Rust 一致: 每个字段值读完后 align4（由 _read_value 收尾）"""
    if r.pos + 8 > len(r.buf):
        raise EOFError
    num_fields, class_hash = struct.unpack_from('<II', r.buf, r.pos)
    r.pos += 8
    for fi in range(num_fields):
        if r.pos + 8 > len(r.buf):
            raise EOFError
        fhash = r.u32()
        ftype = r.i32()
        if ftype < -1 or ftype > 17:
            raise ValueError(f"非法字段类型 {ftype} @pos={r.pos - 4}")
        fpath = f"{path}.f{fi:03d}[{fhash:08x}]"
        _read_value(r, ftype, fields_out, fpath, class_hash, fhash)
    return class_hash


def _read_value(r: Reader, ftype: int, out: list, path: str,
                class_hash: int, fhash: int):
    """读取字段值并 align4 收尾（对应 Rust Field::read 尾部对齐）"""
    buf_len = len(r.buf)
    if ftype == FT_ARRAY:
        r.align(4)
        member_type, member_size, length, array_type = struct.unpack_from('<IiIi', r.buf, r.pos)
        r.pos += 16
        if length > 0x100000:
            raise ValueError(f"数组过长 {length} @pos={r.pos}")
        if array_type == 1:
            if r.pos + 4 <= buf_len and struct.unpack_from('<I', r.buf, r.pos)[0] == 0xFFEEFFEE:
                r.pos += 4 + 4 * length
            for i in range(length):
                read_class(r, out, f"{path}[{i}]")
        else:
            for i in range(length):
                if member_type == FT_STRING:
                    r.align(4)
                    size = r.u32()
                    r.pos += 2 * size
                elif member_type == FT_CLASS:
                    read_class(r, out, f"{path}[{i}]")
                elif member_type == FT_STRUCT:
                    r.align(4)
                    size = r.u32()
                    if size != 1:
                        r.pos = (r.pos + size - 1) & ~(size - 1)
                    r.pos += size
                else:
                    _read_sized(r, member_type, member_size, out,
                                f"{path}[{i}]", class_hash, fhash,
                                read_size=False)
        r.align(4)  # Array::read 尾部对齐
    elif ftype == FT_CLASS:
        read_class(r, out, path)
    elif ftype == FT_STRING:
        r.align(4)
        size = r.u32()
        if size > 0x100000:
            raise ValueError(f"字符串过长 {size}")
        r.pos += 2 * size
    elif ftype == FT_STRUCT:
        r.align(4)
        size = r.u32()
        if size > 0x1000000:
            raise ValueError(f"struct 过大 {size}")
        if size != 1:
            r.pos = (r.pos + size - 1) & ~(size - 1)
        if size == 16:
            # Mandrake 防篡改对 (v: i64, m: i64) — 记录便于读写
            v, m = struct.unpack_from('<qq', r.buf, r.pos)
            out.append(FieldRec(path, class_hash, fhash, r.pos, ftype, (v, m)))
        r.pos += size
    elif ftype == 0:
        pass  # Unknown: 0 字节函数体
    else:
        _read_sized(r, ftype, 4, out, path, class_hash, fhash)
    r.align(4)  # Field::read 尾部对齐


def _read_sized(r: Reader, ftype: int, size: int, out: list, path: str,
                class_hash: int, fhash: int, read_size=True):
    """数字/枚举值。
    普通字段: [align4][u32 size][align(size)][值]
    数组元素: 无 size 前缀（size=member_size）, 仅对齐
    注: ftype=0 (原版标记 Unknown) 实测同样是 [u32 size][数据] 布局"""
    if read_size:
        r.align(4)
        size = r.u32()
    if size != 1:
        # Rust: new_offset = (pos + size - 1) & !(size - 1)
        # 实测确认: Struct size=16 → 对齐 16 (0x59bb8→0x59bc0 场景)
        r.pos = (r.pos + size - 1) & ~(size - 1)
    if size > 0x1000000:
        raise ValueError(f"非法 size={size} @pos={r.pos - 4}")

    # 值的实际宽度: 数值型由类型决定; Enum/Struct/Unknown 由 size 决定
    if ftype in (FT_BOOL, FT_S8, FT_U8, FT_C8):
        width = 1
    elif ftype in (FT_S16, FT_U16, FT_C16):
        width = 2
    elif ftype in (FT_S32, FT_U32, FT_F32):
        width = 4
    elif ftype in (FT_S64, FT_U64, FT_F64):
        width = 8
    else:  # ENUM / STRUCT / Unknown
        width = size

    if r.pos + width > len(r.buf):
        raise EOFError
    val = None
    if width == 4 and ftype != FT_F32:
        val = struct.unpack_from('<I', r.buf, r.pos)[0]
        if ftype == FT_S32:
            val = struct.unpack_from('<i', r.buf, r.pos)[0]
    elif width in (1, 2, 8):
        val = int.from_bytes(r.buf[r.pos:r.pos + width], 'little')

    if ftype in (FT_S32, FT_U32, FT_S64, FT_U64, FT_ENUM) or (ftype == 0 and size == 4):
        out.append(FieldRec(path, class_hash, fhash, r.pos, ftype, val))
    r.pos += width


def parse_rsz(plain: bytes, verbose=False):
    """解析顶层结构流，返回 (顶层 hash 列表, 扁平数字字段记录)
    对齐 Rust 版行为: 单个结构解析失败时跳过继续"""
    r = Reader(plain)
    top = []
    out = []
    end = len(plain) - 7
    fails = 0
    while r.pos < end:
        r.align(4)
        if r.pos + 4 > len(plain):
            break
        h = r.u32()
        try:
            read_class(r, out, f"top[{h:08x}]")
            top.append(h)
        except (EOFError, struct.error, IndexError) as e:
            fails += 1
            if verbose:
                print(f"  [跳过] hash={h:08x} @pos={r.pos}: {e}")
            r.pos += 4  # 跳过当前 hash 字节继续尝试
            if fails > 2000:
                break
    return top, out


def find_save_dirs():
    """扫描各盘符寻找 Steam userdata/<id>/2246340/remote/win64_save
    (Windows 原生 Python 与 WSL 均可运行)"""
    import glob
    import os
    if os.name == 'nt':
        # 注意: 'D:' 会被 os.path.join 当作相对路径, 必须带反斜杠 'D:\\'
        drives = [f'{c}:\\' for c in 'CDEFGHIJKLMNOPQRSTUVWXYZ'
                  if os.path.isdir(f'{c}:\\')]
    else:
        drives = [f'/mnt/{c}' for c in 'cdefghijklmnopqrstuvwxyz'
                  if os.path.isdir(f'/mnt/{c}')]
    hits = []
    for drive in drives:
        for sub in ('Program Files (x86)/Steam', 'Steam', 'SteamLibrary',
                    'Program Files/Steam'):
            pattern = os.path.join(drive, sub, 'userdata', '*',
                                   '2246340', 'remote', 'win64_save')
            hits.extend(glob.glob(pattern))
    result = []
    for h in hits:
        if os.path.isdir(h):
            result.append(h)
    return result


def steamid64_from_userdata(dirpath: str) -> int:
    """userdata/<account_id>/... → SteamID64 (兼容 Windows '\\' 与 POSIX '/' 路径)"""
    import re
    m = re.search(r'userdata[/\\](\d+)', dirpath)
    if not m:
        raise ValueError(f'路径中找不到 userdata/<account_id>: {dirpath}')
    return 0x0110000100000000 + int(m.group(1))
