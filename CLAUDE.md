# CLAUDE.md — Baobox 共享库

给在本仓库干活的会话。读这一页就够上手；架构取舍、各平台差异、怎么发版与升级见
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 这是什么

Baobox 的 **Windows 版**（[`qiaob/baobox_windows`](https://github.com/qiaob/baobox_windows)）与
**Linux 版**（[`qiaob/baobox_linux`](https://github.com/qiaob/baobox_linux)）共用的四个 Rust crate，
放在仓库根目录，组成一个 Cargo workspace：

| crate | 干什么 |
|---|---|
| `baobox-core/` | 纯逻辑，**零依赖**：几何、选区 / 编辑器状态机、标注、拼接、文件名、配置、历史、剪贴板模型、敏感内容、文本格式、片段、防休眠、窗口布局、JSON、AI 用量与会话、键盘点击标签、网络泄露检测的判定 |
| `baobox-app/` | 应用框架：`ToolModule` + `ToolRegistry`、菜单模型、设置声明、快捷键规格、配置文件读取、跨平台的工具 id（`tools/`）、两个 AI 助手工具、网络泄露检测工具 |
| `baobox-render/` | 标注光栅化进 RGBA（逐像素一致）+ 工具条底板与图标（`chrome`） |
| `baobox-image/` | PNG 编解码、灰度（唯一的第三方依赖 `png` 在这里） |

`app` 与 `render` 用 `path = "../baobox-core"` 引 core。macOS 版
（[`qiaob/baobox_mac`](https://github.com/qiaob/baobox_mac)，Swift）不链接这些 crate，但实现的是同一套规格；
产品全貌与 mac 侧约定看那边的根 `CLAUDE.md`。

## 规矩（写代码前必读）

1. **不放平台代码**。不引平台依赖（`windows`、`x11rb`、`gtk`、`zbus`……），不写 `cfg(windows)` /
   `cfg(target_os = …)` 分支，不写 `unsafe`（每个 crate 都开了 `#![forbid(unsafe_code)]`）。
   抓屏、托盘、剪贴板、快捷键注册这类系统能力留在平台仓库，这里也**不为它们定义 trait** ——
   形状差太远，抽象出来谁都不好用。`ToolModule` 是例外：它抽象的是「工具怎么接进 App」，
   每个方法返回的都是平台无关的数据。
2. **只按平台分规则、不按平台分代码**：确实因平台而异的规则（比如文件名消毒）做成参数
   （`Platform` 枚举），两边的规则都在这里、都有测试，在任何开发机上都能跑。
3. **`baobox-core` 保持零依赖**。要第三方库先想想能不能放到别的 crate。
4. **配置里的键名、工具 id、快捷键动作 id 是跨平台契约**：改了，用户的同一份配置换个系统就失效。
   要改就两个平台一起跟，并在提交信息里写清楚。
5. 公开接口一改，两个平台仓库都要跟：先在平台仓库用不提交的 `.cargo/config.toml` 的 `[patch]`
   指到本地检出编一遍（写法见 `docs/ARCHITECTURE.md`「本地同时改共享库和平台代码」），再合并、发标签。
6. 解析外部输入（配置文件、会话日志、剪贴板内容）全程容错：缺字段、类型不对只跳过或降级，
   不 panic（生产代码不 `unwrap` / `expect` 外部数据）。

## 构建与验证

工具链固定 **Rust 1.90.0**（CI 也是；升级时改 `.github/workflows/ci.yml` 和两个平台仓库的工作流，
顺手修掉新冒出来的警告）：

```bash
cargo +1.90.0 fmt --all --check
cargo +1.90.0 clippy --workspace --all-targets -- -D warnings
cargo +1.90.0 test --workspace --all-targets
```

- CI（`.github/workflows/ci.yml`）在 `ubuntu-24.04` 和 `windows-2022` 上各跑一遍这三条，
  推到 `main` / `claude/**` 或手动触发时跑。
- 测试里的常量断言写成 `const { assert!(…) }`（clippy 不许运行期 `assert!(常量)`）。
- `Cargo.lock` 提交；平台仓库按 git 依赖引用时不读它。

## 发版

标签就是版本：四个 crate 的 `version` 改成同一个新号 → 提交 `main` → `git tag vX.Y.Z && git push origin vX.Y.Z`。
**推上去的标签不要挪**。然后在两个平台仓库把四行依赖的 `tag` 改过去、
`cargo update -p baobox-core -p baobox-app -p baobox-image -p baobox-render`、提交锁文件。
完整步骤见 `docs/ARCHITECTURE.md`「改了共享库之后怎么升级」。

## 文档

- `docs/ARCHITECTURE.md` —— 多平台架构：四个仓库各放什么、共用什么、平台差异、各平台进度、引用与升级。
- `docs/ERRORS.md` —— Rust 错误类型化的设计（baobox_mac#110，写于单仓库时期）。
- `docs/MODULE_GLUE.md` —— 模块胶水下沉到 `baobox-app` 的设计（baobox_mac#111，写于单仓库时期）。

2026-11 之前的提交来自单仓库的 `shared/` 目录；那些提交信息和上面两份设计里的 `#数字`
指 `qiaob/baobox_mac` 的 issue / PR。

## Git

- 开发在 feature 分支（`claude/**` 会触发 CI），提交信息用英文 conventional commits，
  末尾带 `Co-Authored-By: Claude <noreply@anthropic.com>`。
- 提交者 `Claude <noreply@anthropic.com>`。
