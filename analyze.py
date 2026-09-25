# -*- coding: utf-8 -*-
"""分析真实存档：解密 → 解析 RSZ → 反查字段名，定位 HR"""
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mhwilds_core import (unpack_save, parse_rsz, murmur3_32,
                          steamid64_from_userdata, FT_S32, FT_U32)

# <SteamID3> 替换为你的 Steam 数字账号 ID（userdata 下的目录名）
SAVE = "/mnt/d/Program Files (x86)/Steam/userdata/<SteamID3>/3351393/remote/win64_save/data001Slot.bin"
STEAMID64 = steamid64_from_userdata(SAVE)
print(f"SteamID64 = {STEAMID64}")

raw = open(SAVE, 'rb').read()
print(f"存档大小 = {len(raw)} 字节")

plain = unpack_save(raw, STEAMID64)
print(f"解密+解压成功! 明文长度 = {len(plain)} (0x{len(plain):x})")

top, fields = parse_rsz(plain)
print(f"顶层结构 {len(top)} 个, 数字字段 {len(fields)} 个")
print(f"顶层 hash: {[f'{h:08x}' for h in top[:10]]}")

# 加载类型表反查名字
data = json.load(gzip.open('/tmp/ree/rszmhwilds.json.gz'))
name_by_class = {}
for h, info in data.items():
    name = info.get('name', '')
    if not name:
        continue
    # class hash 可能 = murmur3_32(类名)，建立映射
    name_by_class[murmur3_32(name.encode())] = name
    # 也直接用 json 的键（可能是别的 hash 算法）
    name_by_class.setdefault(int(h, 16), name)

# 字段名 → hash 映射（全部字段名）
fname_by_hash = {}
for h, info in data.items():
    for f in info.get('fields', []):
        n = f.get('name')
        if n:
            fname_by_hash[murmur3_32(n.encode())] = (n, info.get('name', ''))

print("\n=== 含 rank 的字段（值 + 反查名）===")
seen = set()
for rec in fields:
    key = (rec.path, rec.field_hash)
    if key in seen:
        continue
    seen.add(key)
    fn = fname_by_hash.get(rec.field_hash)
    if fn and 'rank' in fn[0].lower():
        cls = name_by_class.get(rec.class_hash, f"{rec.class_hash:08x}?")
        print(f"{rec.path} value={rec.value} | {fn[0]} @ {cls} "
              f"(offset=0x{rec.offset:x}, type={rec.ftype})")

print("\n=== 前 30 个字段示例 ===")
for rec in fields[:30]:
    fn = fname_by_hash.get(rec.field_hash, ('???',))
    cls = name_by_class.get(rec.class_hash, f"{rec.class_hash:08x}?")
    print(f"offset=0x{rec.offset:06x} value={rec.value:>10} {fn[0]} @ {cls[:60]}")
