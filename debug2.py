# -*- coding: utf-8 -*-
"""逐步解析定位失败点"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mhwilds_core as C

plain = open('/tmp/plain_dump.bin', 'rb').read()
r = C.Reader(plain)

# 手动解析第一个顶层结构
h = r.u32()
print(f"顶层 h = {h:08x}")
num_fields, class_hash = struct.unpack_from('<II', plain, r.pos)
r.pos += 8
print(f"Class: num_fields={num_fields}, hash={class_hash:08x}")

# 只解析 Field 头几个看看
for fi in range(min(num_fields, 5)):
    r.align(4)
    fhash = r.u32()
    ftype = r.i32()
    print(f"  Field[{fi}] hash={fhash:08x} type={ftype} @pos={r.pos}")
    if ftype == -1:
        member_type, member_size, length, array_type = struct.unpack_from('<IiIi', plain, r.pos)
        r.pos += 16
        print(f"    Array: member_type={member_type} member_size={member_size} "
              f"len={length} array_type={array_type} @pos={r.pos}")
        if array_type == 1:
            marker = struct.unpack_from('<I', plain, r.pos)[0]
            print(f"    marker={marker:08x} @pos={r.pos}")
            if marker == 0xFFEEFFEE:
                r.pos += 4
                hashes = struct.unpack_from(f'<{length}I', plain, r.pos)
                r.pos += 4 * length
                print(f"    class hashes: {[f'{x:08x}' for x in hashes[:5]]}")
            # 第一个元素类
            for ei in range(min(length, 2)):
                nf, ch = struct.unpack_from('<II', plain, r.pos)
                print(f"    元素[{ei}] Class num_fields={nf} hash={ch:08x} @pos={r.pos}")
                r.pos += 8
                # 该类前3个字段
                for fj in range(min(nf, 3)):
                    r.align(4)
                    fh = r.u32(); ft = r.i32()
                    print(f"      F[{fj}] hash={fh:08x} type={ft} @pos={r.pos}")
                    if ft in (7, 8):  # S32/U32
                        sz = r.u32()
                        r.pos += sz
                        print(f"        sized={sz}")
                    elif ft == 2:  # bool
                        sz = r.u32(); r.pos += sz
                    elif ft == -1:
                        mt, ms, ln, at = struct.unpack_from('<IiIi', plain, r.pos)
                        print(f"        inner array mt={mt} ms={ms} len={ln} at={at}")
                        break
                    else:
                        break
                break
        break
