# -*- coding: utf-8 -*-
"""Roundtrip 验证: 解密→patch→加密→再解密→逐字节比对"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mhwilds_core import (unpack_save, pack_save, parse_rsz, murmur3_32,
                          steamid64_from_userdata)

# <SteamID3> 替换为你的 Steam 数字账号 ID（userdata 下的目录名）
SAVE = "/mnt/d/Program Files (x86)/Steam/userdata/<SteamID3>/2246340/remote/win64_save/data001Slot.bin"
SID = steamid64_from_userdata(SAVE)

raw = open(SAVE, 'rb').read()
plain = unpack_save(raw, SID)
print(f"[1] 解密成功: 明文 {len(plain)} 字节")

HUNTERPOINT_HASH = murmur3_32(b"HunterPoint")

# 找槽位0 的 HunterPoint
top, fields = parse_rsz(plain)
rec = next(r for r in fields if r.field_hash == HUNTERPOINT_HASH and '[0]' in r.path)
v, m = rec.value
hrp = v // m
print(f"[2] 槽位0 HunterPoint: v={v}, m={m}, HRP={hrp}, offset={rec.offset:#x}")

# patch: HRP 提到 9999999
NEW_HRP = 9999999
patched = bytearray(plain)
struct.pack_into('<q', patched, rec.offset, NEW_HRP * m)
print(f"[3] patch 完成: HRP {hrp} -> {NEW_HRP}")

# 重新加密
new_file = pack_save(bytes(patched), SID)
print(f"[4] 加密完成: 新文件 {len(new_file)} 字节 (原 {len(raw)})")

# 重新解密验证
plain2 = unpack_save(new_file, SID)
print(f"[5] 重新解密成功: {len(plain2)} 字节")

# 逐字节比对 (仅允许 patch 的 8 字节不同)
diffs = [i for i in range(len(plain)) if plain[i] != plain2[i]]
expected = set(range(rec.offset, rec.offset + 8))
unexpected = [i for i in diffs if i not in expected]
print(f"[6] 差异字节数: {len(diffs)} (均在预期 8 字节内), 越界差异: {len(unexpected)}")
assert not unexpected and len(diffs) <= 8, "ROUNDTRIP 失败!"
print(f"[7] ROUNDTRIP 完美通过! 差异仅在偏移 {rec.offset:#x} 的 8 字节 v 值")

# 验证新值可被正确解析
v2, m2 = struct.unpack_from('<qq', plain2, rec.offset)
print(f"[8] 新 HunterPoint: v={v2}, m={m2}, HRP={v2//m2}")
assert v2 // m2 == NEW_HRP and m2 == m
print("\n=== 全部验证通过, 可以安全写回 ===")
