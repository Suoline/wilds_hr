# -*- coding: utf-8 -*-
"""调试: 用 Elgamal 认证块验证 key/iv 生成链路是否正确"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mhwilds_core import (MASK64, sm64, WILDS_SEED_ENC, BLOCK_UNIT, AUTH_SIZE,
                          ELGAMAL_P, ELGAMAL_Q, cityhash64)

# <SteamID3> 替换为你的 Steam 数字账号 ID（userdata 下的目录名）
SAVE = "/mnt/d/Program Files (x86)/Steam/userdata/<SteamID3>/2246340/remote/win64_save/data001Slot.bin"
STEAMID64 = 0x0110000100000000 + 0  # TODO: 加上你的 SteamID3

raw = open(SAVE, 'rb').read()
decrypted_len = struct.unpack_from('<Q', raw, len(raw) - 12)[0]
enc = raw[16:len(raw) - 4]
print(f"decrypted_len={decrypted_len} (0x{decrypted_len:x}), enc长度={len(enc)}")

n_pot = ((decrypted_len & 0x3FFF) != 0) + (decrypted_len >> 14)
sizes = []
state = WILDS_SEED_ENC
for _ in range(n_pot):
    sizes.append((state & 7) + 1)
    state = sm64(state)
print(f"块大小序列(前8): {sizes[:8]} × 0x4000")

key = STEAMID64
state = (state + (~key & MASK64)) & MASK64

# 块 0
block_size = sizes[0] * BLOCK_UNIT
buf = bytearray(enc[0:block_size + AUTH_SIZE])
print(f"块0: size=0x{block_size:x}, enc_read=0x{block_size + AUTH_SIZE:x}")

k16 = bytearray(16)
iv16 = bytearray(16)
for j in range(16):
    state = sm64(state)
    k16[j] = state & 0xFF
    iv16[j] = (state >> 8) & 0xFF
print(f"PRNG 生成的 key = {bytes(k16).hex()}")
print(f"PRNG 生成的 iv  = {bytes(iv16).hex()}")

for j in range(AUTH_SIZE):
    state = sm64(state)
    buf[j] ^= state & 0xFF

# Elgamal 解出块头里记录的 key/iv
u = (~key & MASK64) % ELGAMAL_Q
recovered = b''
for c in range(4):
    x0 = int.from_bytes(buf[c*128:c*128+64], 'little')
    ct = int.from_bytes(buf[c*128+64:(c+1)*128], 'little')
    if x0 == 0 and ct == 0:
        print(f"pair {c}: 全 0"); recovered += b'\x00'*8; continue
    x = pow(x0, u, ELGAMAL_P)
    if x == 0 or ct % x != 0:
        print(f"pair {c}: 不能整除! x={x % 1000}")
        recovered += b'\x00'*8
        continue
    k = ct // x
    recovered += k.to_bytes(8, 'little')

print(f"Elgamal 恢复的 key/iv = {recovered.hex()}")
rk, riv = recovered[:16], recovered[16:32]
print(f"key 匹配: {rk == bytes(k16)}, iv 匹配: {riv == bytes(iv16)}")

target = struct.unpack_from('<Q', buf, 0x200)[0]
print(f"目标 checksum = {target:#018x}")
print(f"unk8 = {buf[0x208:0x210].hex()}")
