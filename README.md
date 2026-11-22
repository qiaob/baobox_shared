# baobox_shared

[![CI](https://github.com/qiaob/baobox_shared/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaob/baobox_shared/actions/workflows/ci.yml)

[English](#english) · [简体中文](#简体中文)

## English

The Rust libraries shared by the **Windows** and **Linux** versions of
[Baobox](https://github.com/qiaob/baobox_mac), a tray / menu-bar toolbox (screenshots, clipboard
history, window management, keep-awake, keyboard clicking, Claude Code / Codex dashboards).

Everything here is platform-independent: pure logic and plain data, no OS APIs, no `unsafe`.
The platform repositories call into it directly; there are no platform traits to implement.

| Crate | What it is |
|---|---|
| [`baobox-core`](baobox-core) | Pure logic, zero dependencies: geometry, the selection and annotation-editor state machines, annotation model with undo, scrolling-capture stitching, toolbar layout, OCR reading order, hotkey parsing, filename templates (per-platform sanitizing), line-preserving INI config, screenshot and clipboard history, sensitive-content detection, text-format detection and conversion, snippets, keep-awake timing, window-layout geometry, a small JSON parser, AI usage / session-log parsing, keyboard-clicking hint labels |
| [`baobox-app`](baobox-app) | The app framework: the `ToolModule` trait and `ToolRegistry` (registration order = menu order), tray menu model, settings declarations, hotkey specs, config-file loading, and the two AI assistant tools (they need nothing from the platform except a terminal launcher) |
| [`baobox-render`](baobox-render) | Rasterizes annotations into an RGBA buffer, pixel-identical on every platform; also draws the toolbar chrome and icons |
| [`baobox-image`](baobox-image) | RGBA → PNG (file or memory), PNG → RGBA, RGBA → grayscale |

### Who uses it

| Repository | |
|---|---|
| [qiaob/baobox_windows](https://github.com/qiaob/baobox_windows) | Windows (Rust + Win32/GDI) |
| [qiaob/baobox_linux](https://github.com/qiaob/baobox_linux) | Linux (Rust + X11 + GTK3) |
| [qiaob/baobox_mac](https://github.com/qiaob/baobox_mac) | macOS (Swift) — doesn't link these crates, but implements the same specs |

The platform repositories depend on a tag:

```toml
baobox-core = { git = "https://github.com/qiaob/baobox_shared", tag = "v0.1.0" }
# … the same for baobox-app, baobox-image, baobox-render — always the same tag on all four
```

### Develop

The four crates form one Cargo workspace. Toolchain pinned to **Rust 1.90.0** for linting:

```bash
cargo +1.90.0 fmt --all --check
cargo +1.90.0 clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

CI runs all three on Linux and Windows. How to release a new tag and upgrade the platform
repositories: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (Chinese).

History before November 2026 comes from the `shared/` directory of the Baobox monorepo
(`qiaob/baobox_mac`); `#123` in those commit messages refers to issues and PRs there.

## 简体中文

[Baobox](https://github.com/qiaob/baobox_mac)（托盘 / 菜单栏效率工具集合：截图、剪贴板历史、窗口管理、防休眠、
键盘点击、Claude Code / Codex 用量面板）**Windows 版与 Linux 版共用的 Rust 库**。

这里只放与操作系统无关的东西：纯逻辑、纯数据结构，不碰系统 API，不写 `unsafe`。
平台仓库直接调用，没有要实现的平台 trait。

| crate | 是什么 |
|---|---|
| [`baobox-core`](baobox-core) | 纯逻辑，零依赖：几何运算、选区与标注编辑器状态机、标注模型与撤销、长截屏拼接、工具条布局、OCR 阅读顺序、快捷键解析、文件名模板（按平台消毒）、行级 INI 配置、截图与剪贴板历史、敏感内容识别、文本格式识别与转换、文本片段、防休眠计时、窗口布局几何、小型 JSON 解析器、AI 用量与会话日志、键盘点击的标签发号 |
| [`baobox-app`](baobox-app) | 应用框架：`ToolModule` trait 与 `ToolRegistry`（注册顺序 = 菜单顺序）、托盘菜单模型、设置声明、快捷键规格、配置文件读取，以及两个 AI 助手工具（除了「开哪个终端」不需要平台提供任何东西） |
| [`baobox-render`](baobox-render) | 把标注光栅化进 RGBA 缓冲，三平台逐像素一致；工具条底板与图标也是这里画的 |
| [`baobox-image`](baobox-image) | RGBA → PNG（文件或内存）、PNG → RGBA、RGBA → 灰度 |

### 谁在用

| 仓库 | |
|---|---|
| [qiaob/baobox_windows](https://github.com/qiaob/baobox_windows) | Windows（Rust + Win32/GDI） |
| [qiaob/baobox_linux](https://github.com/qiaob/baobox_linux) | Linux（Rust + X11 + GTK3） |
| [qiaob/baobox_mac](https://github.com/qiaob/baobox_mac) | macOS（Swift）—— 不链接这些 crate，但实现的是同一套规格 |

平台仓库按标签引用：

```toml
baobox-core = { git = "https://github.com/qiaob/baobox_shared", tag = "v0.1.0" }
# baobox-app、baobox-image、baobox-render 同样写法 —— 四行永远是同一个标签
```

### 开发

四个 crate 是一个 Cargo workspace。lint 用的工具链固定 **Rust 1.90.0**：

```bash
cargo +1.90.0 fmt --all --check
cargo +1.90.0 clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

CI 在 Linux 和 Windows 上各跑一遍这三条。怎么发新标签、怎么在两个平台仓库里升级：
见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

2026-11 之前的提交历史来自 Baobox 单仓库（`qiaob/baobox_mac`）的 `shared/` 目录，
那些提交信息里的 `#123` 指的是那边的 issue / PR。
