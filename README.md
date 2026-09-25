# 《怪物猎人：荒野》存档修改器（免费开源版）

一个本地运行的 Python 小工具，可以查看和修改《怪物猎人：荒野》(Monster Hunter Wilds)
存档里的**猎人等级点数(HRP)**、**金钱**等数值。不联网、不收费、无广告。

## 文件说明

| 文件 | 作用 |
|---|---|
| `mhwilds_gui.py` | **图形界面版（推荐）**，免敲命令 |
| `dist/MHWildsSaveEditor.exe` | 图形界面打包版，双击即用（免 Python） |
| `mhwilds_hr.py` | 命令行版 |
| `mhwilds_core.py` | 核心库（Mandarin 加解密 / RSZ 解析） |

依赖: Python 3.8+。`cryptography` 库可选（`pip install cryptography`，
装了加解密更快；不装也能用，走纯 Python 回退）。
Windows 官方 Python 自带 tkinter，无需额外安装。

## 使用方法（图形界面，推荐）

1. **完全退出游戏**（Steam 可以开着）
2. 双击 `dist\MHWildsSaveEditor.exe`（或 `python mhwilds_gui.py`）
3. 自动扫描并加载存档，显示各槽位角色名和数值
4. 选择槽位，在「新值」栏填数字（**留空 = 不修改**，填 0 是合法值）
5. 点「写入修改」→ 确认 diff 对话框 → 完成
6. 改错了点「恢复最近备份」即可回滚

界面为 Windows 11 深色风格（sv-ttk 主题），状态栏彩色圆点指示当前状态
（蓝=工作中 / 绿=就绪 / 黄=有未写入的修改 / 红=出错）。
写回前同样做 roundtrip 校验并自动备份，与命令行版一致。

> exe 首次启动要解压到临时目录，稍慢几秒属正常；
> Windows SmartScreen / 杀软可能误报自打包 exe，放行即可。

### 重新打包 exe（可选）

```powershell
pip install pyinstaller cryptography sv-ttk
pyinstaller --onefile --windowed --name MHWildsSaveEditor --collect-all sv_ttk mhwilds_gui.py
```

产物在 `dist\MHWildsSaveEditor.exe`。

## 使用方法（命令行）

### 第一步：完全退出游戏
确认怪物猎人荒野已关闭（Steam 可以开着，但改完前别启动游戏）。

### 第二步：先查看当前存档

```bash
cd ~/wilds_hr
python3 mhwilds_hr.py
```

会自动找到 Steam 存档并显示（示例）：

```
=== 角色槽位 1: Luna ===
  猎人等级点数(HRP)      =        881,762
  金钱(zenny)        =      5,101,156
  ...
```

### 第三步：修改

```bash
# 把猎人等级点数拉到 5000 万（足够 HR999）
python3 mhwilds_hr.py --hrp 50000000

# 同时改金钱为 9999 万
python3 mhwilds_hr.py --hrp 50000000 --money 99999999

# 第 2 个角色槽位
python3 mhwilds_hr.py --slot 2 --hrp 50000000

# 先试试看不写入
python3 mhwilds_hr.py --hrp 50000000 --dry-run
```

### 关于 HRP 和 HR 的关系

- 游戏里显示的猎人等级(HR)是由 HRP 累积换算的，HRP 越高 HR 越高
- HR999 大约需要几百万 HRP，**设 5000 万基本必到 999**（上限还受剧情解放进度影响）
- 改完进游戏看一眼，如果 HR 没到 999，把 HRP 再调大即可

### 出问题时恢复

每次修改都会自动备份（存档同目录下 `.bak` 文件）：

```bash
python3 mhwilds_hr.py --restore
```

## 安全机制

1. **自动备份**: 每次写回前生成 `data001Slot.bin.时间戳.bak`
2. **roundtrip 校验**: 修改后先用新数据重新加密→解密→逐字节比对，
   只有差异严格落在目标 8 字节内才写入，否则放弃
3. **只 patch 不重建**: 只改目标字段的 8 字节，存档其余 1600 万字节原封不动
4. **m 掩码保持不变**: 采用游戏的 Mandrake 防篡改结构(v = 真实值 × m)，
   只改 v、不动 m，与游戏自身的写入方式一致

## Steam 云存档提示

修改后第一次启动游戏时，Steam 可能提示"云同步冲突"，
选择**保留本地文件 / 上传本地存档**即可。

## ⚠️ 风险提示

- 修改联机游戏的存档违反 Capcom 使用条款，理论上存在封号风险。
  建议不要把数值改得离谱（比如 HR 直接 999 配 0 游戏时长），保持低调。
- 本工具只修改本地存档文件，不注入游戏进程（比内存修改器更不容易被反作弊检测，
  但没有任何人能保证 100% 安全）。
- 使用风险自负。

## 技术原理（给感兴趣的玩家）

《荒野》存档格式（RE 引擎 `DSSS` v2）:

```
文件 = DSSS头(12B) + 对齐(4B)
     + Mandarin加密层  ← AES-128-OFB 分块, 密钥流由 SplitMix64 生成,
     │                    密钥 = 你的 SteamID64, 块头是 Elgamal 认证块,
     │                    CityHash64 数据校验, 尾部附 RSA 加密的密钥材料
     + DEFLATE 压缩层 ← 标准 raw deflate
     + RSZ 结构层     ← 字段树, 字段名以 murmur3_32(名字, 0xFFFFFFFF) 哈希存储
```

关键数值(HRP/金钱等)用 Mandrake 防篡改结构存储: 16 字节 = (v: i64, m: i64)，
游戏读取时做 `v / m`。修改时写入 `新值 × m` 即可。

参考了开源项目 [kvasszn/ree-save-editor](https://github.com/kvasszn/ree-save-editor)
的加密算法逆向成果（Elgamal/SplitMix64/AES 流程），RSZ 解析部分根据真实存档
逐字节验证修正（包括原版未处理的 type=0 字段和数组元素无 size 前缀的细节）。
