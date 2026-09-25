# -*- coding: utf-8 -*-
"""严格模式解析: 越界立即抛异常, 打印字段轨迹"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mhwilds_core as C


class StrictReader(C.Reader):
    def _chk(self, n):
        if self.pos + n > len(self.buf):
            raise EOFError(f"越界 @pos={self.pos} +{n} > {len(self.buf)}")

    def u8(self):
        self._chk(1); return super().u8()

    def u16(self):
        self._chk(2); return super().u16()

    def u32(self):
        self._chk(4); return super().u32()

    def i32(self):
        self._chk(4); return super().i32()


trace = []
TRACING = [True]


def trace_read_class(r, path, depth=0):
    if depth > 30:
        raise ValueError("过深")
    r._chk(8)
    num_fields, class_hash = struct.unpack_from('<II', r.buf, r.pos)
    if num_fields > 5000:
        raise ValueError(f"num_fields 异常: {num_fields} @pos={r.pos}")
    r.pos += 8
    if TRACING[0]:
        trace.append(f"{'  '*depth}CLASS {path} nf={num_fields} hash={class_hash:08x} @pos={r.pos}")
    for fi in range(num_fields):
        r.align(4)
        r._chk(8)
        fhash = r.u32()
        ftype = r.i32()
        if ftype < -1 or ftype > 17:
            raise ValueError(f"非法字段类型 {ftype} @pos={r.pos-4} field_hash={fhash:08x}")
        fpath = f"{path}.f{fi:03d}[{fhash:08x}]"
        trace_val(r, ftype, fpath, class_hash, fhash, depth)


def trace_val(r, ftype, path, cls_hash, fhash, depth):
    if ftype == 0:
        return  # Unknown: 0 字节
    if ftype == C.FT_ARRAY:
        r.align(4)
        r._chk(16)
        mt, ms, ln, at = struct.unpack_from('<IiIi', r.buf, r.pos)
        r.pos += 16
        if TRACING[0] and len(trace) < 400:
            trace.append(f"{'  '*depth}ARRAY {path} mt={mt} ms={ms} len={ln} at={at} @pos={r.pos}")
        if ln > 100000:
            raise ValueError(f"数组过长 {ln} @pos={r.pos}")
        if at == 1:
            if r.pos + 4 <= len(r.buf):
                marker = struct.unpack_from('<I', r.buf, r.pos)[0]
                if marker == 0xFFEEFFEE:
                    r.pos += 4
                    r._chk(4 * ln)
                    r.pos += 4 * ln
            for i in range(ln):
                trace_read_class(r, f"{path}[{i}]", depth + 1)
        else:
            for i in range(ln):
                if mt == C.FT_STRING:
                    r.align(4); r._chk(4)
                    sz = r.u32()
                    if sz > 1000000: raise ValueError(f"字符串过长 {sz}")
                    r._chk(2 * sz); r.pos += 2 * sz
                elif mt == C.FT_CLASS:
                    trace_read_class(r, f"{path}[{i}]", depth + 1)
                elif mt == C.FT_STRUCT:
                    r.align(4); r._chk(4)
                    sz = r.u32()
                    if sz > 10000000: raise ValueError(f"struct 过大 {sz}")
                    r._chk(sz); r.pos += sz
                else:
                    trace_sized(r, mt, ms, path + f"[{i}]")
    elif ftype == C.FT_CLASS:
        trace_read_class(r, path, depth + 1)
    elif ftype == C.FT_STRING:
        r.align(4); r._chk(4)
        sz = r.u32()
        if sz > 1000000: raise ValueError(f"字符串过长 {sz} @pos={r.pos-4}")
        r._chk(2 * sz); r.pos += 2 * sz
    elif ftype == C.FT_STRUCT:
        r.align(4); r._chk(4)
        sz = r.u32()
        if sz > 10000000: raise ValueError(f"struct 过大 {sz}")
        r._chk(sz); r.pos += sz
    else:
        trace_sized(r, ftype, 4, path)


def trace_sized(r, ftype, size, path):
    r.align(4); r._chk(4)
    sz = r.u32()
    if sz not in (1, 2, 4, 8):
        raise ValueError(f"非法 size={sz} @pos={r.pos-4} path={path}")
    if sz != 1:
        r.align(sz)
    if TRACING[0] and len(trace) < 400:
        trace.append(f"{'  '}VAL {path} type={ftype} sz={sz} @pos={r.pos}")
    r._chk(sz); r.pos += sz


plain = open('/tmp/plain_dump.bin', 'rb').read()
r = StrictReader(plain)
h = r.u32()
try:
    trace_read_class(r, f"top[{h:08x}]")
    print("第一个顶层结构解析成功!")
except Exception as e:
    print(f"失败: {e}")
print(f"\n=== 轨迹 (最后 60 条) ===")
for line in trace[-60:]:
    print(line)
