#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
《怪物猎人：荒野》存档修改器 (免费开源版)
================================================
功能: 查看/修改 猎人等级点数(HRP, 决定猎人等级HR)、金钱、各类点数
原理: 解密 Steam 存档(data001Slot.bin, Mandarin加密) → 修改RSZ明文 → 重新加密写回
安全: 每次修改自动备份; 写回前做完整 roundtrip 校验; 只patch目标字节, 不重建结构

用法:
  python3 mhwilds_hr.py                  # 查看当前存档信息
  python3 mhwilds_hr.py --hrp 5000000    # 设置猎人等级点数为 500万 (冲HR999)
  python3 mhwilds_hr.py --money 30000000 # 设置金钱为 3000万
  python3 mhwilds_hr.py --slot 2 --hrp 5000000  # 指定角色槽位(1-3, 默认1)
  python3 mhwilds_hr.py --restore        # 恢复最近一次备份

注意: 修改前请完全退出游戏!
风险: 修改联机游戏存档违反 Capcom 服务条款, 理论上有封号风险, 请自行斟酌。
"""
import argparse
import glob
import os
import shutil
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mhwilds_core import (unpack_save, pack_save, parse_rsz, murmur3_32,
                          find_save_dirs, steamid64_from_userdata)

# cBasicParam 中的 Mandrake 防篡改字段 (16字节: v = 真实值 * m)
MANDRAKE_FIELDS = {
    'HunterPoint':   '猎人等级点数(HRP)',
    'Money':         '金钱(zenny)',
    'TotalMoney':    '累计获得金钱',
    'Point':         '点数',
    'TotalPoint':    '累计点数',
    'LuckyTicket':   '抽奖券',
}
MANDRAKE_HASHES = {murmur3_32(k.encode()): k for k in MANDRAKE_FIELDS}
HP_HASH = murmur3_32(b'HunterPoint')


def slot_index_of(rec):
    """从字段路径提取槽位序号 (路径第2段 = f000[hash][N])"""
    try:
        return int(rec.path.split('.')[1].split('[')[-1].rstrip(']'))
    except (IndexError, ValueError):
        return None


def read_slot_info(plain):
    """返回 {槽位序号: {'fields': {字段名: (v, m, offset, 真实值)}}}"""
    top, fields = parse_rsz(plain)
    slots = {}
    for rec in fields:
        if rec.ftype != 16:
            continue
        key = MANDRAKE_HASHES.get(rec.field_hash)
        if not key:
            continue
        si = slot_index_of(rec)
        if si is None:
            continue
        v, m = rec.value
        slots.setdefault(si, {'fields': {}})['fields'][key] = \
            (v, m, rec.offset, v // m if m else 0)
    return slots


def get_char_name(plain, slot):
    """提取槽位猎人名。
    实测布局: HunterPoint(16B Mandrake)数据后 0x10 处起是 String 字段
    (CharName / OtomoName / SeikretName / PugeeName)"""
    top, fields = parse_rsz(plain)
    for rec in fields:
        if rec.field_hash == HP_HASH and rec.ftype == 16 \
                and slot_index_of(rec) == slot:
            p = rec.offset + 0x10
            if p + 12 <= len(plain) \
                    and struct.unpack_from('<I', plain, p + 4)[0] == 0x0F:
                n = struct.unpack_from('<I', plain, p + 8)[0]
                try:
                    return plain[p + 12:p + 12 + 2 * n].decode('utf-16-le')
                except Exception:
                    pass
            break
    return '(未知)'


def backup(save_path):
    bak = f"{save_path}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
    shutil.copy2(save_path, bak)
    return bak


def latest_backup(save_path):
    baks = sorted(glob.glob(save_path + '.*.bak'))
    return baks[-1] if baks else None


def main():
    ap = argparse.ArgumentParser(
        description='《怪物猎人：荒野》存档修改器 (免费版)')
    ap.add_argument('--hrp', type=int, help='设置猎人等级点数 HRP (决定猎人等级 HR)')
    ap.add_argument('--money', type=int, help='设置金钱(zenny)')
    ap.add_argument('--slot', type=int, default=1, choices=(1, 2, 3),
                    help='角色槽位 1-3 (默认 1)')
    ap.add_argument('--save', help='手动指定存档文件路径 (data001Slot.bin)')
    ap.add_argument('--restore', action='store_true', help='恢复最近一次备份')
    ap.add_argument('--dry-run', action='store_true', help='试运行, 不写回文件')
    args = ap.parse_args()

    # ---- 定位存档 ----
    if args.save:
        save_path = args.save
        sid = steamid64_from_userdata(save_path)
    else:
        found = find_save_dirs()
        if not found:
            print('错误: 未找到《怪物猎人：荒野》存档目录!')
            print("请确认 Steam userdata 下存在 2246340 目录, 或用 --save 指定路径")
            sys.exit(1)
        if len(found) > 1:
            print('发现多个 Steam 账号的存档:')
            for i, d in enumerate(found):
                print(f'  [{i}] {d}')
            sel = input('选择序号 (回车默认 0): ').strip() or '0'
            d = found[int(sel)]
        else:
            d = found[0]
        sid = steamid64_from_userdata(d)
        save_path = os.path.join(d, 'data001Slot.bin')

    if not os.path.exists(save_path):
        print(f'错误: 存档文件不存在: {save_path}')
        sys.exit(1)

    # ---- 恢复模式 ----
    if args.restore:
        bak = latest_backup(save_path)
        if not bak:
            print('没有找到备份文件')
            sys.exit(1)
        shutil.copy2(bak, save_path)
        print(f'已恢复备份: {bak}')
        return

    print(f'存档: {save_path}')
    print(f'SteamID64: {sid}')
    raw = open(save_path, 'rb').read()

    try:
        plain = unpack_save(raw, sid)
    except Exception as e:
        print(f'解密失败: {e}')
        sys.exit(1)

    slot_idx = args.slot - 1
    slots = read_slot_info(plain)
    if slot_idx not in slots:
        print(f'槽位 {args.slot} 没有角色数据 (现有槽位: '
              f'{sorted(k + 1 for k in slots)})')
        sys.exit(1)

    name = get_char_name(plain, slot_idx)
    print(f'\n=== 角色槽位 {args.slot}: {name} ===')
    for key, label in MANDRAKE_FIELDS.items():
        if key in slots[slot_idx]['fields']:
            v, m, off, real = slots[slot_idx]['fields'][key]
            print(f'  {label:16s} = {real:>14,}')

    if not args.hrp and not args.money:
        print('\n(查看模式, 未修改。 用 --hrp N 或 --money N 修改, --help 看说明)')
        return

    # ---- 应用修改 ----
    patched = bytearray(plain)
    patch_offsets = []
    changes = []
    targets = [('HunterPoint', args.hrp, '猎人等级点数(HRP)'),
               ('Money', args.money, '金钱(zenny)')]
    for key, target, label in targets:
        if target is None:
            continue
        if key not in slots[slot_idx]['fields']:
            print(f'错误: 找不到 {label} 字段')
            sys.exit(1)
        if target < 0:
            print('错误: 数值不能为负')
            sys.exit(1)
        v, m, off, real = slots[slot_idx]['fields'][key]
        new_v = target * m
        if abs(new_v) > 2 ** 63 - 1:
            print(f'错误: {label} 数值过大 (上限 {(2**63 - 1) // m:,})')
            sys.exit(1)
        struct.pack_into('<q', patched, off, new_v)
        patch_offsets.append(off)
        changes.append(f'{label}: {real:,} → {target:,}')

    print('\n将应用修改:')
    for c in changes:
        print(f'  {c}')
    if args.dry_run:
        print('(试运行, 未写回)')
        return

    # ---- roundtrip 校验 ----
    new_file = pack_save(bytes(patched), sid)
    verify = unpack_save(new_file, sid)
    assert len(verify) == len(plain)
    bad = [i for i in range(len(plain))
           if plain[i] != verify[i]
           and not any(off <= i < off + 8 for off in patch_offsets)]
    if bad:
        print(f'内部校验失败 (意外差异 {len(bad)} 字节), 已放弃写入, 原文件未动')
        sys.exit(1)
    for off in patch_offsets:
        assert verify[off:off + 8] == bytes(patched[off:off + 8])

    bak = backup(save_path)
    print(f'\n已备份原存档 → {bak}')
    with open(save_path, 'wb') as f:
        f.write(new_file)
    print(f'已写入新存档 ({len(new_file):,} 字节), 解密回读校验通过 ✓')
    print('\n提示:')
    print('  · 启动游戏即可看到新的猎人等级/金钱')
    print('  · HRP 越高 HR 越高 (上限 999 或你当前已解放的上限)')
    print('  · 若 Steam 弹出云同步冲突, 选择「保留本地文件 / 上传本地存档」')


if __name__ == '__main__':
    main()
