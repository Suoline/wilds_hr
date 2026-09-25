# -*- coding: utf-8 -*-
"""最终语义的轨迹解析器, 与 mhwilds_core 保持一致"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mhwilds_core as C

plain = open('/tmp/plain_dump.bin', 'rb').read()
r = C.Reader(plain)
trace = []


def tclass(path, depth=0):
    if r.pos + 8 > len(plain):
        raise EOFError
    nf, ch = struct.unpack_from('<II', plain, r.pos)
    if nf > 5000:
        raise ValueError(f"nf={nf} 异常 @{r.pos:#x}")
    r.pos += 8
    trace.append(f"{'  '*depth}C {path} nf={nf} h={ch:08x} @{r.pos:#x}")
    for fi in range(nf):
        if r.pos + 8 > len(plain):
            raise EOFError
        fh = r.u32()
        ft = r.i32()
        if ft < -1 or ft > 17:
            raise ValueError(f"非法type={ft} @{r.pos-4:#x} (fh={fh:08x})")
        tval(ft, f"{path}.f{fi}[{fh:08x}]", depth)
        r.align(4)


def tval(ft, path, depth):
    if ft == -1:
        r.align(4)
        mt, ms, ln, at = struct.unpack_from('<IiIi', plain, r.pos)
        r.pos += 16
        trace.append(f"{'  '*depth}A {path} mt={mt} ms={ms} len={ln} at={at} @{r.pos:#x}")
        if ln > 0x100000:
            raise ValueError("len 过大")
        if at == 1:
            if r.pos + 4 <= len(plain) and struct.unpack_from('<I', plain, r.pos)[0] == 0xFFEEFFEE:
                r.pos += 4 + 4 * ln
            for i in range(ln):
                tclass(f"{path}[{i}]", depth + 1)
        else:
            for i in range(ln):
                if mt == 15:
                    r.align(4); sz = r.u32(); r.pos += 2 * sz
                elif mt == 17:
                    tclass(f"{path}[{i}]", depth + 1)
                elif mt == 16:
                    r.align(4); sz = r.u32(); r.pos += sz
                else:
                    tsized(mt, ms, read_size=False)
        r.align(4)
    elif ft == 17:
        tclass(path, depth + 1)
    elif ft == 15:
        r.align(4); sz = r.u32()
        if sz > 0x100000: raise ValueError("str 过长")
        r.pos += 2 * sz
    elif ft == 16:
        r.align(4); sz = r.u32()
        if sz > 0x1000000: raise ValueError("struct 过大")
        r.pos += sz
    elif ft == 0:
        pass
    else:
        tsized(ft, 4)


def tsized(ft, size, read_size=True):
    if read_size:
        r.align(4)
        size = r.u32()
        if size > 0x1000000:
            raise ValueError(f"size={size} 异常 @{r.pos-4:#x}")
    if size != 1:
        r.pos = (r.pos + size - 1) & ~(size - 1)
    width = {2: 1, 3: 1, 4: 1, 13: 1, 5: 2, 6: 2, 14: 2,
             7: 4, 8: 4, 11: 4, 9: 8, 10: 8, 12: 8}.get(ft, size)
    if len(trace) < 300:
        trace.append(f"  V type={ft} sz={size} @{r.pos:#x} w={width}")
    r.pos += width


h = r.u32()
try:
    tclass(f"top[{h:08x}]")
    print("第一个顶层结构解析成功!")
except Exception as e:
    print(f"失败: {e}")
print(f"\n=== 轨迹最后 45 条 ===")
for line in trace[-45:]:
    print(line)
