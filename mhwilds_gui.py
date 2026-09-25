#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
《怪物猎人：荒野》存档修改器 — 图形界面版
================================================
与命令行版 (mhwilds_hr.py) 共用核心库 mhwilds_core.py, 功能:
自动查找存档 / 选择角色槽位 / 修改 6 项数值 / 写入(自动备份+roundtrip校验) / 恢复备份

用法:
  python mhwilds_gui.py           # 打开图形界面
  python mhwilds_gui.py --smoke   # 自测: 构建界面 0.8 秒后自动退出 (无人工介入)

零第三方依赖 (tkinter 为 Python 自带; cryptography 可选, 加速加解密)。
"""
import argparse
import os
import queue
import shutil
import struct
import sys
import threading
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mhwilds_core import (unpack_save, pack_save, parse_rsz, find_save_dirs,
                          steamid64_from_userdata, ChecksumError)
from mhwilds_hr import (MANDRAKE_FIELDS, MANDRAKE_HASHES, HP_HASH,
                        slot_index_of, backup, latest_backup)

# tkinter 用守卫导入: 无 python3-tk / 无显示环境时仍可 import 本模块做逻辑层测试
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    _HAS_TK = True
except ImportError:
    _HAS_TK = False

# sv-ttk (Windows 11 Sun Valley 主题) 可选: 缺失时回退 ttk 原生主题
try:
    import sv_ttk
    _HAS_SV = True
except ImportError:
    sv_ttk = None
    _HAS_SV = False

# 深色主题色板 (Sun Valley dark)
C_BG = '#202020'          # 窗口底
C_CARD = '#2b2b2b'        # 卡片底
C_TEXT = '#e8e8e8'        # 主文字
C_DIM = '#9a9a9a'         # 次要文字
C_ACCENT = '#4cc2ff'      # 数值/强调 (Win11 亮蓝)
C_OK = '#3fb950'
C_DIRTY = '#d29922'
C_ERR = '#f85149'
STATUS_COLORS = {'idle': C_DIM, 'busy': C_ACCENT, 'ok': C_OK,
                 'dirty': C_DIRTY, 'error': C_ERR}

MAX_I63 = 2 ** 63 - 1

# 数值字段图标 (顺序同 MANDRAKE_FIELDS)
FIELD_ICONS = {'HunterPoint': '⭐', 'Money': '💰', 'TotalMoney': '📈',
               'Point': '💠', 'TotalPoint': '🔹', 'LuckyTicket': '🎫'}


# ============================================================
# 纯逻辑层 (无任何 tk 引用, 可在无显示环境单测)
# ============================================================

class Plan:
    """一次写入的修改计划。targets 元素: (key, label, 旧真实值, 新目标值, 新v, 偏移)"""
    __slots__ = ('targets', 'offsets')

    def __init__(self, targets, offsets):
        self.targets = targets
        self.offsets = offsets


def validate_and_plan(slot_fields, user_inputs):
    """校验用户输入并生成修改计划。
    slot_fields: {字段名: (v, m, offset, 真实值)}  — read_slot_info 的产物
    user_inputs: {字段名: str}  — Entry 文本; 留空 = 不修改 (填 0 是合法修改)
    抛 ValueError(中文, 面向用户)。"""
    targets, offsets = [], []
    for key, text in user_inputs.items():
        t = (text or '').strip()
        if not t:
            continue                      # 留空 = 不修改
        if not t.isdigit():
            raise ValueError(f'「{MANDRAKE_FIELDS[key]}」请输入非负整数')
        target = int(t)
        v, m, off, real = slot_fields[key]
        new_v = target * m
        if new_v > MAX_I63:               # target>=0, m>0, 无需判负
            raise ValueError(f'「{MANDRAKE_FIELDS[key]}」超出上限 '
                             f'{MAX_I63 // m:,}')
        targets.append((key, MANDRAKE_FIELDS[key], real, target, new_v, off))
        offsets.append(off)
    if not targets:
        raise ValueError('没有填写任何要修改的数值')
    return Plan(targets, offsets)


def patch_plain(plain, plan):
    """按偏移把 new_v 写入明文副本 (只动目标 8 字节, 与 CLI 一致)。"""
    patched = bytearray(plain)
    for key, label, real, target, new_v, off in plan.targets:
        struct.pack_into('<q', patched, off, new_v)
    return bytes(patched)


def roundtrip_verify(plain, patched, offsets, sid):
    """pack→unpack→逐字节比对: 除目标 8 字节窗口外不得有任何差异。
    通过返回可写盘的密文 bytes, 否则抛 ValueError (绝不写盘)。"""
    new_file = pack_save(patched, sid)
    verify = unpack_save(new_file, sid)
    if len(verify) != len(plain):
        raise ValueError(f'roundtrip 长度不一致 ({len(verify):,} != {len(plain):,})')
    bad = sum(1 for i in range(len(plain))
              if plain[i] != verify[i]
              and not any(off <= i < off + 8 for off in offsets))
    if bad:
        raise ValueError(f'内部校验失败 (意外差异 {bad} 字节), 已放弃写入')
    for off in offsets:
        if verify[off:off + 8] != patched[off:off + 8]:
            raise ValueError('目标字节回读不一致, 已放弃写入')
    return new_file


def analyze_plain(plain):
    """一次 parse_rsz 同时提取各槽位 Mandrake 字段与猎人名
    (避免对每个槽位重复整档解析)。返回 ({si: {字段: (v,m,off,real)}}, {si: 名字})"""
    slots, hp_off_by_slot = {}, {}
    for rec in parse_rsz(plain)[1]:
        if rec.ftype != 16:
            continue
        si = slot_index_of(rec)
        if si is None:
            continue
        key = MANDRAKE_HASHES.get(rec.field_hash)
        if key:
            v, m = rec.value
            slots.setdefault(si, {})[key] = (v, m, rec.offset, v // m if m else 0)
        if rec.field_hash == HP_HASH:
            hp_off_by_slot[si] = rec.offset
    names = {si: _read_char_name(plain, off) for si, off in hp_off_by_slot.items()}
    return slots, names


def _read_char_name(plain, hp_offset):
    """读 HunterPoint 数据后 0x10 处的 String 字段 (与 CLI get_char_name 同布局)。"""
    p = hp_offset + 0x10
    if p + 12 <= len(plain) \
            and struct.unpack_from('<I', plain, p + 4)[0] == 0x0F:
        n = struct.unpack_from('<I', plain, p + 8)[0]
        try:
            return plain[p + 12:p + 12 + 2 * n].decode('utf-16-le')
        except Exception:
            pass
    return '(未知)'


# ============================================================
# GUI
# ============================================================

class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self._busy = False
        self._pending_load = None             # busy 期间收到的加载请求, done 后补发
        self._io_lock = threading.Lock()      # 磁盘写互斥 (backup+write / restore)
        # 已加载的存档上下文
        self.save_path = None
        self.sid = None
        self.raw = None
        self.plain = None
        self.slots = {}                       # {si: {字段: (v,m,off,real)}}
        self.names = {}                       # {si: 猎人名}

        root.title('怪物猎人：荒野 存档修改器')
        root.minsize(560, 480)
        self._build_ui()
        self._poll()
        root.protocol('WM_DELETE_WINDOW', root.destroy)
        # 启动即后台扫描存档
        self._spawn(self._find_worker)

    # ---------- UI 构建 ----------

    def _build_ui(self):
        import tkinter.font as tkfont
        root = self.root
        win = sys.platform == 'win32'
        ui = 'Microsoft YaHei UI' if win else \
            tkfont.nametofont('TkDefaultFont').actual('family')
        mono = 'Consolas' if win else \
            tkfont.nametofont('TkFixedFont').actual('family')
        F_TITLE = (ui, 16, 'bold')
        F_BODY = (ui, 10)
        F_SMALL = (ui, 9)
        F_VALUE = (mono, 11)

        # ---- 主题 ----
        style = ttk.Style(root)
        if _HAS_SV:
            sv_ttk.set_theme('dark')
            root.configure(background=C_BG)
            for s, kw in {
                'Card.TFrame': {'background': C_CARD},
                'Card.TLabel': {'background': C_CARD, 'foreground': C_TEXT, 'font': F_BODY},
                'CardDim.TLabel': {'background': C_CARD, 'foreground': C_DIM, 'font': F_SMALL},
                'CardValue.TLabel': {'background': C_CARD, 'foreground': C_ACCENT, 'font': F_VALUE},
                'Card.TRadiobutton': {'background': C_CARD, 'font': F_BODY},
                'Title.TLabel': {'background': C_BG, 'foreground': C_TEXT, 'font': F_TITLE},
                'Dim.TLabel': {'background': C_BG, 'foreground': C_DIM, 'font': F_SMALL},
                'Status.TLabel': {'background': C_BG, 'foreground': C_TEXT, 'font': F_SMALL},
                'Statusbar.TFrame': {'background': C_BG},
                'Body.TFrame': {'background': C_BG},
            }.items():
                style.configure(s, **kw)
            style.map('Card.TRadiobutton',
                      background=[('selected', C_CARD), ('active', C_CARD)],
                      foreground=[('disabled', '#5a5a5a')])
            btn_accent = 'Accent.TButton'
        else:
            style.configure('Card.TFrame', font=F_BODY)
            style.configure('CardValue.TLabel', font=F_VALUE)
            style.configure('Title.TLabel', font=F_TITLE)
            style.configure('Dim.TLabel', font=F_SMALL)
            style.configure('Status.TLabel', font=F_SMALL)
            btn_accent = 'TButton'

        # ---- 状态栏 (先 pack, 避免被 expand 的主区挤成零高度) ----
        sbar = ttk.Frame(root, style='Statusbar.TFrame')
        sbar.pack(side='bottom', fill='x')
        self.status_var = tk.StringVar(value='正在扫描 Steam 存档目录…')
        self.dot_lbl = ttk.Label(sbar, text='●', style='Status.TLabel',
                                 padding=(16, 6, 6, 6))
        self.dot_lbl.pack(side='left')
        ttk.Label(sbar, textvariable=self.status_var, style='Status.TLabel',
                  padding=(0, 6, 16, 6)).pack(side='left', fill='x')

        # ---- 主区 ----
        main = ttk.Frame(root, padding=(18, 14, 18, 10), style='Body.TFrame'
                         if _HAS_SV else 'TFrame')
        main.pack(fill='both', expand=True)

        # 标题行
        hdr = ttk.Frame(main, style='Body.TFrame' if _HAS_SV else 'TFrame')
        hdr.pack(fill='x', pady=(0, 12))
        ttk.Label(hdr, text='⚔  怪物猎人：荒野', style='Title.TLabel') \
            .pack(side='left')
        self.sid_lbl = ttk.Label(hdr, text='', style='Dim.TLabel', anchor='e')
        self.sid_lbl.pack(side='right')

        # 存档路径行
        prow = ttk.Frame(main, style='Body.TFrame' if _HAS_SV else 'TFrame')
        prow.pack(fill='x', pady=(0, 4))
        self.dir_var = tk.StringVar()
        self.dir_box = ttk.Combobox(prow, textvariable=self.dir_var,
                                    state='readonly', font=F_SMALL)
        self.dir_box.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.dir_box.bind('<<ComboboxSelected>>',
                          lambda e: self._start_load(self.dir_var.get()))
        ttk.Button(prow, text='🔄 自动查找', command=self._on_find) \
            .pack(side='left', padx=(0, 6))
        ttk.Button(prow, text='📂 浏览…', command=self._on_browse) \
            .pack(side='left')
        self.file_lbl = ttk.Label(main, text='存档未加载', style='Dim.TLabel',
                                  anchor='w', font=F_SMALL)
        self.file_lbl.pack(fill='x', pady=(0, 10))

        # 卡片: 角色槽位
        c1 = ttk.Frame(main, style='Card.TFrame', padding=(14, 10, 14, 12))
        c1.pack(fill='x', pady=(0, 10))
        ttk.Label(c1, text='角 色', style='CardDim.TLabel') \
            .pack(anchor='w', pady=(0, 6))
        slotrow = ttk.Frame(c1, style='Card.TFrame')
        slotrow.pack(fill='x')
        self.slot_var = tk.IntVar(value=0)
        self.slot_btns = []
        for i in range(3):
            rb = ttk.Radiobutton(slotrow, text=f' 槽位 {i + 1} · (未加载) ',
                                 value=i, variable=self.slot_var,
                                 command=self._refresh_fields, state='disabled',
                                 style='Card.TRadiobutton')
            rb.pack(side='left', padx=(0, 18))
            self.slot_btns.append(rb)

        # 卡片: 数值
        c2 = ttk.Frame(main, style='Card.TFrame', padding=(14, 10, 14, 12))
        c2.pack(fill='both', expand=True, pady=(0, 12))
        ttk.Label(c2, text='数 值      新值留空 = 不修改', style='CardDim.TLabel') \
            .pack(anchor='w', pady=(0, 8))
        grid = ttk.Frame(c2, style='Card.TFrame')
        grid.pack(fill='both', expand=True)
        ttk.Label(grid, text='字段', style='CardDim.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(grid, text='当前值', style='CardDim.TLabel').grid(row=0, column=1, sticky='e')
        ttk.Label(grid, text='新值', style='CardDim.TLabel').grid(row=0, column=3, sticky='w')
        self.value_lbls, self.entry_vars, self.entries = {}, {}, {}
        for r, (key, label) in enumerate(MANDRAKE_FIELDS.items(), start=1):
            ttk.Label(grid, text=f'{FIELD_ICONS[key]}  {label}',
                      style='Card.TLabel').grid(row=r, column=0, sticky='w', pady=3)
            vlbl = ttk.Label(grid, text='—', width=13, anchor='e',
                             style='CardValue.TLabel')
            vlbl.grid(row=r, column=1, sticky='e', padx=(10, 10), pady=3)
            self.value_lbls[key] = vlbl
            ttk.Label(grid, text='→', style='CardDim.TLabel', anchor='center') \
                .grid(row=r, column=2)
            var = tk.StringVar()
            var.trace_add('write', lambda *a: self._on_dirty_input())
            ent = ttk.Entry(grid, textvariable=var, width=14, justify='right',
                            font=F_VALUE, state='disabled')
            ent.grid(row=r, column=3, sticky='we', pady=3)
            self.entry_vars[key] = var
            self.entries[key] = ent
        grid.columnconfigure(0, weight=1)

        # 操作行
        brow = ttk.Frame(main, style='Body.TFrame' if _HAS_SV else 'TFrame')
        brow.pack(fill='x', pady=(0, 8))
        self.write_btn = ttk.Button(brow, text='💾  写入修改', style=btn_accent,
                                    command=self._on_write)
        self.write_btn.pack(side='right')
        self.restore_btn = ttk.Button(brow, text='↩  恢复最近备份', state='disabled',
                                      command=self._on_restore)
        self.restore_btn.pack(side='right', padx=(0, 10))
        self.reload_btn = ttk.Button(brow, text='🔄 重新读取', state='disabled',
                                     command=self._on_reload)
        self.reload_btn.pack(side='right')
        self._set_status('正在扫描 Steam 存档目录…', 'busy')

    # ---------- 状态控制 ----------

    def _set_interactive(self, enabled):
        """除"自动查找/浏览"外的交互控件统一开关。
        busy 结束时 (enabled=True) 只有已加载存档才恢复可交互。"""
        st = 'normal' if (enabled and self.slots) else 'disabled'
        for rb in self.slot_btns:
            rb.configure(state=st)
        for ent in self.entries.values():
            ent.configure(state=st)
        self.write_btn.configure(state=st)
        self.reload_btn.configure(state=st)
        self.restore_btn.configure(
            state='normal' if (enabled and self.slots and self.save_path
                               and latest_backup(self.save_path))
            else 'disabled')

    def _set_status(self, text, kind='idle'):
        """状态栏统一入口。kind: idle灰 busy蓝 ok绿 dirty黄 error红"""
        self.status_var.set(text)
        self.dot_lbl.configure(foreground=STATUS_COLORS.get(kind, C_DIM))

    def _on_dirty_input(self):
        if self.save_path:
            self._set_status('有未写入的修改 · 写入前请完全退出游戏', 'dirty')

    # ---------- 轮询与 worker 调度 ----------

    def _poll(self):
        """主线程唯一消费 worker 结果的入口 (tkinter 非线程安全, 官方推荐模式)。"""
        try:
            while True:
                kind, payload = self.q.get_nowait()
                getattr(self, f'_on_{kind}')(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _spawn(self, fn):
        if self._busy:
            return
        self._busy = True
        self._set_interactive(False)

        def wrapped():
            try:
                fn()
            except Exception:
                self.q.put(('fatal', traceback.format_exc()))
            finally:
                self.q.put(('done', None))

        threading.Thread(target=wrapped, daemon=True).start()

    # ---------- workers (后台线程, 只通过 queue 说话) ----------

    def _find_worker(self):
        self.q.put(('found', find_save_dirs()))

    def _load_worker(self, save_path):
        try:
            sid = steamid64_from_userdata(save_path)
        except ValueError as e:
            self.q.put(('error', ('路径错误',
                                  f'{e}\n路径需形如 …/userdata/<数字ID>/2246340/…')))
            return
        try:
            with open(save_path, 'rb') as f:
                raw = f.read()
            plain = unpack_save(raw, sid)
        except ChecksumError:
            self.q.put(('error', ('解密失败',
                                  '校验失败: SteamID64 与存档不匹配, '
                                  '请确认选的是该 Steam 账号的 userdata 目录')))
            return
        except ValueError as e:
            self.q.put(('error', ('解密失败',
                                  f'文件损坏或不是《怪物猎人：荒野》存档: {e}')))
            return
        except OSError as e:
            self.q.put(('error', ('读取失败', str(e))))
            return
        self.q.put(('status', '正在解析存档结构…'))
        slots, names = analyze_plain(plain)
        if not slots:
            self.q.put(('error', ('解析失败', '存档里没有找到任何角色数据')))
            return
        self.q.put(('loaded', {'path': save_path, 'sid': sid, 'raw': raw,
                               'plain': plain, 'slots': slots, 'names': names}))

    def _write_worker(self, plan):
        # 新鲜度检查: 加载后文件若被改动 (游戏未退出/云同步), 放弃
        try:
            with open(self.save_path, 'rb') as f:
                raw2 = f.read()
        except OSError as e:
            self.q.put(('error', ('写入失败', str(e))))
            return
        if raw2 != self.raw:
            self.q.put(('error', ('存档已变化',
                                  '加载之后存档文件被修改过 (游戏未退出或云同步), '
                                  '已放弃写入。请点「重新读取」后重试。')))
            return
        try:
            patched = patch_plain(self.plain, plan)
            new_file = roundtrip_verify(self.plain, patched, plan.offsets, self.sid)
            with self._io_lock:
                bak = backup(self.save_path)
                with open(self.save_path, 'wb') as f:
                    f.write(new_file)
        except PermissionError:
            self.q.put(('error', ('写入失败',
                                  '文件可能被游戏占用, 请完全退出游戏后重试')))
            return
        except OSError as e:
            self.q.put(('error', ('写入失败', str(e))))
            return
        # ValueError(roundtrip) 会落到 _spawn 的 fatal → 显示完整 traceback, 便于排查
        self.q.put(('written', {'bak': bak, 'size': len(new_file)}))

    def _restore_worker(self):
        bak = latest_backup(self.save_path)
        if not bak:
            self.q.put(('error', ('恢复失败', '没有找到备份文件')))
            return
        try:
            with self._io_lock:
                shutil.copy2(bak, self.save_path)
        except OSError as e:
            self.q.put(('error', ('恢复失败', str(e))))
            return
        self.q.put(('restored', bak))

    # ---------- 轮询消息处理 (主线程) ----------

    def _on_found(self, dirs):
        if not dirs:
            self._set_status('未找到存档目录 · 请点「浏览…」手动选择 data001Slot.bin', 'error')
            messagebox.showinfo(
                '未找到存档',
                '未自动找到《怪物猎人：荒野》存档目录。\n'
                '请点「浏览…」手动选择存档文件:\n'
                r'…\Steam\userdata\<数字ID>\2246340\remote\win64_save\data001Slot.bin')
            return
        if len(dirs) == 1:
            self.dir_box['values'] = dirs
            self.dir_var.set(dirs[0])
            self._defer_load(dirs[0])
        else:
            self.dir_box['values'] = dirs
            self.dir_var.set(dirs[0])
            self._set_status(f'发现 {len(dirs)} 个 Steam 账号的存档 · 请在下拉框选择', 'idle')

    def _on_loaded(self, ctx):
        self.save_path = ctx['path']
        self.sid = ctx['sid']
        self.raw = ctx['raw']
        self.plain = ctx['plain']
        self.slots = ctx['slots']
        self.names = ctx['names']
        self.file_lbl.configure(text=f'存档文件: {self.save_path}')
        self.sid_lbl.configure(text=f'SteamID64: {self.sid}')
        for i, rb in enumerate(self.slot_btns):
            rb.configure(text=f' 槽位 {i + 1} · {self.names.get(i, "(空)")} ')
        # 默认选第一个有角色的槽位
        self.slot_var.set(min(self.slots))
        for key, var in self.entry_vars.items():
            var.set('')
        self._refresh_fields()
        self._set_status(
            f'已加载 · 角色 {self.names.get(self.slot_var.get(), "?")} — 填写新值后写入',
            'ok')

    def _on_written(self, info):
        self._set_status(f'已写入 ✓ 备份: {os.path.basename(info["bak"])}', 'ok')
        messagebox.showinfo(
            '写入成功',
            f'已写入新存档 ({info["size"]:,} 字节), 解密回读校验通过。\n'
            f'备份: {os.path.basename(info["bak"])}\n\n'
            '提示: 若 Steam 弹出云同步冲突, 选择「保留本地文件 / 上传本地存档」。')
        # 自动重新读盘刷新显示
        self._defer_load(self.save_path)

    def _on_restored(self, bak):
        self._set_status(f'已恢复备份 · {os.path.basename(bak)}', 'ok')
        self._defer_load(self.save_path)

    def _on_status(self, text):
        self._set_status(text, 'busy')

    def _on_error(self, pair):
        title, message = pair
        self._set_status(title, 'error')
        messagebox.showerror(title, message)

    def _on_fatal(self, tb_str):
        self._set_status('发生内部错误', 'error')
        messagebox.showerror('内部错误',
                             f'发生未预期的错误, 原存档未被修改。\n\n{tb_str}')

    def _on_done(self, _):
        self._busy = False
        self._set_interactive(True)
        # busy 期间收到的加载请求 (如扫描完成后自动加载 / 写入后重读) 在此补发
        if self._pending_load:
            path, self._pending_load = self._pending_load, None
            self._start_load(path)

    def _defer_load(self, path):
        """worker 结果回调里发起的加载: 此时 done 尚未消费, busy 仍为 True, 需延迟。"""
        if self._busy:
            self._pending_load = path
        else:
            self._start_load(path)

    # ---------- 用户动作 (主线程) ----------

    def _on_find(self):
        self._set_status('正在扫描 Steam 存档目录…', 'busy')
        self._spawn(self._find_worker)

    def _on_browse(self):
        path = filedialog.askopenfilename(
            title='选择《怪物猎人：荒野》存档文件',
            filetypes=[('存档文件', 'data001Slot.bin'), ('所有文件', '*.*')])
        if path:
            self._start_load(path)

    def _on_reload(self):
        if self.save_path:
            self._set_status('正在重新读取存档…', 'busy')
            self._spawn(lambda: self._load_worker(self.save_path))

    def _start_load(self, path):
        if os.path.isdir(path):
            path = os.path.join(path, 'data001Slot.bin')
        if not os.path.exists(path):
            messagebox.showerror('文件不存在', f'存档文件不存在:\n{path}')
            return
        self._set_status('正在解密存档…', 'busy')
        self._spawn(lambda: self._load_worker(path))

    def _refresh_fields(self):
        si = self.slot_var.get()
        fields = self.slots.get(si, {})
        for key in MANDRAKE_FIELDS:
            v, m, off, real = fields.get(key, (0, 0, 0, 0))
            self.value_lbls[key].configure(
                text=f'{real:,}' if key in fields else '-')

    def _on_write(self):
        si = self.slot_var.get()
        if si not in self.slots:
            messagebox.showerror('错误', '该槽位没有角色数据')
            return
        try:
            plan = validate_and_plan(
                self.slots[si],
                {k: v.get() for k, v in self.entry_vars.items()})
        except ValueError as e:
            messagebox.showerror('输入错误', str(e))
            return
        diff = '\n'.join(f'  {label}: {real:,} → {target:,}'
                         for _, label, real, target, _, _ in plan.targets)
        if not messagebox.askyesno(
                '确认写入',
                f'将应用以下修改:\n{diff}\n\n'
                '请确认游戏已完全退出。\n写入前会自动备份, 确定写入吗?',
                icon='warning'):
            return
        self._set_status('正在加密校验并写入…', 'busy')
        self._spawn(lambda: self._write_worker(plan))

    def _on_restore(self):
        bak = latest_backup(self.save_path) if self.save_path else None
        if not bak:
            messagebox.showinfo('恢复', '没有找到备份文件')
            return
        if not messagebox.askyesno(
                '确认恢复',
                f'将用备份覆盖当前存档:\n{os.path.basename(bak)}\n\n'
                '当前未写入的修改会丢失, 确定恢复吗?', icon='warning'):
            return
        self._set_status('正在恢复备份…', 'busy')
        self._spawn(self._restore_worker)


# ============================================================
# 入口
# ============================================================

def main():
    ap = argparse.ArgumentParser(description='《怪物猎人：荒野》存档修改器 (图形界面)')
    ap.add_argument('--smoke', action='store_true',
                    help='自测: 构建界面 0.8 秒后自动退出')
    args = ap.parse_args()

    if not _HAS_TK:
        print('错误: 当前 Python 缺少 tkinter (Linux 下需 python3-tk)。')
        print('Windows 官方 Python 自带 tkinter, 不会出现此问题。')
        sys.exit(1)

    # Windows 高分屏 DPI 感知 (避免字体发虚), 失败无害
    if sys.platform == 'win32':
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    app = App(root)
    if args.smoke:
        # 自动化验证模式: 静默所有对话框, 等自动加载完成 (最多 30s) 后退出
        _mb = messagebox
        _mb.showinfo = _mb.showerror = _mb.showwarning = lambda *a, **k: None
        _mb.askyesno = lambda *a, **k: False
        import time as _time
        _t0 = _time.monotonic()
        _smoke_failed = [False]

        def _smoke_check():
            if app.slots:                       # 加载成功
                root.destroy()
            elif _time.monotonic() - _t0 > 30:  # 超时 → 标记失败
                _smoke_failed[0] = True
                root.destroy()
            else:
                root.after(200, _smoke_check)

        root.after(800, _smoke_check)
    root.mainloop()
    if args.smoke and _smoke_failed[0]:
        sys.exit(2)


if __name__ == '__main__':
    main()
