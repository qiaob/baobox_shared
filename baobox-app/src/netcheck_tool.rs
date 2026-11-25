//! 网络泄露检测工具接进 App 框架。
//!
//! 检测逻辑与判定全在 `baobox_core::netcheck`；这里负责**按顺序把请求发出去、
//! 把回包交给判定、把结论放进菜单**。
//!
//! # 与平台的接触面
//!
//! 两个函数，由平台层在构造时传进来（与 AI 助手的 `OpenTerminal` 同一个做法）：
//!
//! - [`HttpGet`]：发一个 HTTPS GET，返回响应正文。Rust 标准库没有 TLS，
//!   Windows 用 WinHTTP、Linux 用各自的 HTTP 库，形状差太远，所以不在这里实现
//! - [`SystemTimezone`]：系统当前的 IANA 时区名（`Asia/Singapore`）。
//!   Linux 读 `/etc/localtime` 的链接目标，Windows 要从 Windows 时区名换算
//!
//! 另有一个**可选**的 [`WebrtcProbe`]：在内置浏览器里建一个 `RTCPeerConnection`，
//! 收集 ICE 候选原文。Mac 用隐藏的 `WKWebView`；Windows / Linux 将来接 WebView2 /
//! WebKitGTK。平台不给（[`NetcheckTool::with_webrtc`] 没调），WebRTC 那一项就不测，
//! 报告里写「本平台不检测」。
//!
//! DNS 探测用标准库的系统解析器（[`std::net::ToSocketAddrs`]）—— 那正是要测的那条路：
//! 系统把查询交给谁，bash.ws 就看到谁。
//!
//! # 只在用户点了才测
//!
//! 每次检测都会把出口 IP 告诉 ipapi.is 与 bash.ws，这是检测本身绕不开的。
//! 所以**启动时不自动测、也不定时测**，只在点「立即检测」时测一次。
//!
//! # 跑在后台
//!
//! 一次检测要发五六个请求、解析一串域名，网络慢时十几秒。在菜单线程里跑会把托盘卡死，
//! 所以起一条线程，结果从 channel 回来，在 [`ToolModule::tick`] 里收下。

use crate::{now_seconds, Field, MenuItem, SettingsPage, ToolModule};
use baobox_core::aiusage::short_duration;
use baobox_core::config::Config;
use baobox_core::netcheck::{
    self, DnsResult, Finding, IpInfo, Observations, RealNetworks, Verdict,
};
use std::net::ToSocketAddrs;
use std::sync::mpsc::{channel, Receiver};

/// 工具 id，也是配置文件里的节名。跨平台契约，不要改。
pub const ID: &str = "netcheck";
/// 动作：立即检测。
pub const RUN: &str = "netcheck.run";
/// 动作：上次检测的完整报告。
pub const REPORT: &str = "netcheck.report";

/// 发一个 HTTPS GET，返回响应正文；连不上、超时、非 2xx 都返回 `Err(原因)`。
///
/// 由平台层实现，**要设超时**（建议 10 秒）：DNS 探测与 IPv6 探测在网络不通时会一直等。
pub type HttpGet = fn(url: &str) -> Result<String, String>;

/// 系统当前的 IANA 时区名。拿不到返回 `None`（时区那一项就报「测不出」）。
pub type SystemTimezone = fn() -> Option<String>;

/// 在内置浏览器里跑 WebRTC，经给定的 STUN 服务器（`stun:host:port`）收集 ICE 候选，
/// 返回候选原文（`candidate:…`），一条一个。浏览器起不来、超时返回 `Err(原因)`；
/// 收集完一条都没有返回 `Ok(空)`（UDP 被挡住了，这是不会漏的情况）。
///
/// 会在后台线程里被调用，平台要自己切回 UI 线程建浏览器、阻塞等结果（**要设超时**）。
pub type WebrtcProbe = fn(stun: &str) -> Result<Vec<String>, String>;

/// 用系统解析器解析一个域名。结果不要紧，要的是「查询发出去了」。
pub type Resolve = fn(host: &str);

/// 用标准库的系统解析器解析：走的就是系统真实的 DNS 设置。
pub fn resolve_with_system(host: &str) {
    let _ = (host, 0).to_socket_addrs();
}

/// 从配置读出来的设置。
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// IP 归属服务（ipapi.is 的接口地址）
    pub ip_endpoint: String,
    /// 只有 IPv6 地址的「我的 IP」服务：连得上就说明有 IPv6 出口
    pub ipv6_endpoint: String,
    /// DNS 泄露检测服务（bash.ws）
    pub dns_endpoint: String,
    /// ipapi.is 的 key。留空用匿名档：没有机房 / VPN 判定，退回内置的云厂商表
    pub api_key: String,
    /// 用户声明的真实网络（ASN 列表）
    pub real_networks: String,
    /// DNS 探测解析几个域名
    pub dns_probes: usize,
    /// WebRTC 用的 STUN 服务器
    pub stun_server: String,
}

impl Settings {
    /// 出厂默认值。
    pub fn defaults() -> Self {
        Self {
            ip_endpoint: "https://api.ipapi.is/".to_string(),
            ipv6_endpoint: "https://api6.ipify.org".to_string(),
            dns_endpoint: "https://bash.ws".to_string(),
            api_key: String::new(),
            real_networks: String::new(),
            dns_probes: 10,
            stun_server: "stun:stun.l.google.com:19302".to_string(),
        }
    }

    /// 从配置读。空串按默认值处理（用户把地址清空不该让检测失效）。
    pub fn read(config: &Config) -> Self {
        let defaults = Self::defaults();
        let or_default = |key: &str, fallback: &str| {
            let value = config.string_or(ID, key, fallback);
            if value.trim().is_empty() {
                fallback.to_string()
            } else {
                value.trim().to_string()
            }
        };
        Self {
            ip_endpoint: or_default("ip_endpoint", &defaults.ip_endpoint),
            ipv6_endpoint: or_default("ipv6_endpoint", &defaults.ipv6_endpoint),
            dns_endpoint: or_default("dns_endpoint", &defaults.dns_endpoint),
            api_key: config.string_or(ID, "api_key", "").trim().to_string(),
            real_networks: config.string_or(ID, "real_networks", ""),
            dns_probes: config
                .usize_or(ID, "dns_probes", defaults.dns_probes)
                .clamp(1, 50),
            stun_server: or_default("stun_server", &defaults.stun_server),
        }
    }
}

/// 一次检测要用的平台能力。
#[derive(Clone, Copy)]
pub struct Env {
    /// HTTPS GET
    pub http_get: HttpGet,
    /// 系统时区
    pub system_timezone: SystemTimezone,
    /// 系统解析器
    pub resolve: Resolve,
    /// 内置浏览器跑 WebRTC。`None` = 这个平台不测
    pub webrtc: Option<WebrtcProbe>,
}

/// 在一个地址后面拼查询参数，已经有 `?` 就用 `&`。
fn with_query(base: &str, query: &str) -> String {
    if query.is_empty() {
        return base.to_string();
    }
    let joiner = if base.contains('?') { '&' } else { '?' };
    format!("{base}{joiner}{query}")
}

/// ipapi.is 的查询参数：`q=<ip>` 与 `key=<key>`，没有就不带。
fn ipapi_query(ip: Option<&str>, key: &str) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = ip {
        parts.push(format!("q={ip}"));
    }
    if !key.is_empty() {
        parts.push(format!("key={key}"));
    }
    parts.join("&")
}

/// 查一个 IP 的归属。`ip` 为 `None` 时查请求方自己。
fn lookup(settings: &Settings, env: &Env, ip: Option<&str>) -> Result<IpInfo, String> {
    let url = with_query(&settings.ip_endpoint, &ipapi_query(ip, &settings.api_key));
    let body = (env.http_get)(&url)?;
    netcheck::parse_ipapi(&body).ok_or_else(|| "IP 归属服务的回包看不懂".to_string())
}

/// IPv6 出口：连得上纯 IPv6 的服务就有，连不上就当没有。
///
/// 「连不上」与「没有 IPv6」在这里分不开 —— 没有 IPv6 的网络上，纯 IPv6 的地址
/// 本来就连不上。所以失败一律按「没有 IPv6 出口」，这正是不会漏的那种情况。
fn ipv6_exit(settings: &Settings, env: &Env) -> Result<Option<IpInfo>, String> {
    let Ok(body) = (env.http_get)(&settings.ipv6_endpoint) else {
        return Ok(None);
    };
    let ip = body.trim();
    if !ip.contains(':') {
        // 回了个 IPv4（服务被换成了双栈的）：说明这个地址测不了 IPv6
        return Err(format!("{} 回的不是 IPv6 地址", settings.ipv6_endpoint));
    }
    lookup(settings, env, Some(ip)).map(Some)
}

/// DNS 泄露：拿 id → 解析一串带 id 的域名 → 取结果。
fn dns_leak(settings: &Settings, env: &Env) -> Result<DnsResult, String> {
    let base = settings.dns_endpoint.trim_end_matches('/');
    let host = base
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or("");
    if host.is_empty() {
        return Err("DNS 检测服务的地址不对".to_string());
    }
    let id = (env.http_get)(&format!("{base}/id"))?.trim().to_string();
    // id 要拼进域名：只收字母数字，别让一个异常回包把任意文字塞进 DNS 查询
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("拿到的测试 id 不对".to_string());
    }
    for i in 1..=settings.dns_probes {
        (env.resolve)(&format!("{i}.{id}.{host}"));
    }
    let body = (env.http_get)(&format!("{base}/dnsleak/test/{id}?json=2"))?;
    netcheck::parse_bashws(&body).ok_or_else(|| "DNS 检测服务的回包看不懂".to_string())
}

/// 跑一次完整检测（阻塞，在后台线程里调）。
pub fn run_checks(settings: &Settings, env: &Env) -> Observations {
    Observations {
        ipv4: lookup(settings, env, None),
        ipv6: ipv6_exit(settings, env),
        dns: dns_leak(settings, env),
        system_timezone: (env.system_timezone)(),
        webrtc: env.webrtc.map(|probe| probe(&settings.stun_server)),
    }
}

/// 一次检测的结果。
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// 什么时候测完的（Unix 秒）
    pub at: i64,
    /// 两个问题的回答（[`netcheck::summarize`]）
    pub summary: Vec<Finding>,
    /// 各项结论
    pub findings: Vec<Finding>,
    /// bash.ws 自己的结论文字（有的话）
    pub dns_conclusion: Option<String>,
}

/// 整体结论的一句话。
fn headline(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Ok => "没有发现泄露",
        Verdict::Notice => "没有泄露，但有能被看出来的地方",
        Verdict::Leak => "有泄露",
        Verdict::Unknown => "有几项没测出来",
    }
}

/// 网络泄露检测工具。
pub struct NetcheckTool {
    env: Env,
    settings: Settings,
    last: Option<Outcome>,
    inbox: Option<Receiver<Outcome>>,
}

impl NetcheckTool {
    /// 造一个。两个函数由平台层给；DNS 探测用系统解析器。
    pub fn new(http_get: HttpGet, system_timezone: SystemTimezone) -> Self {
        Self::with_env(Env {
            http_get,
            system_timezone,
            resolve: resolve_with_system,
            webrtc: None,
        })
    }

    /// 平台有内置浏览器：加上 WebRTC 那一项。
    pub fn with_webrtc(mut self, probe: WebrtcProbe) -> Self {
        self.env.webrtc = Some(probe);
        self
    }

    /// 连解析器也换掉（测试用）。
    pub fn with_env(env: Env) -> Self {
        Self {
            env,
            settings: Settings::defaults(),
            last: None,
            inbox: None,
        }
    }

    /// 有没有检测正在跑。
    pub fn running(&self) -> bool {
        self.inbox.is_some()
    }

    /// 上次的结果。
    pub fn last(&self) -> Option<&Outcome> {
        self.last.as_ref()
    }

    /// 起一次后台检测。已经在跑就不重复起。
    fn start(&mut self) {
        if self.running() {
            return;
        }
        let (tx, rx) = channel();
        self.inbox = Some(rx);
        let settings = self.settings.clone();
        let env = self.env;
        std::thread::spawn(move || {
            let observations = run_checks(&settings, &env);
            let real = RealNetworks::parse(&settings.real_networks);
            let dns_conclusion = observations
                .dns
                .as_ref()
                .ok()
                .and_then(|d| d.conclusion.clone());
            let findings = netcheck::evaluate(&observations, &real);
            let _ = tx.send(Outcome {
                at: now_seconds(),
                summary: netcheck::summarize(&observations, &findings),
                findings,
                dns_conclusion,
            });
        });
    }

    /// 完整报告：标题 + 两个问题的回答 + 每项一行 + bash.ws 的原话 + 提示。
    pub fn report_text(&self) -> Option<String> {
        let outcome = self.last.as_ref()?;
        let mut lines = vec![format!(
            "网络泄露检测：{}",
            headline(netcheck::overall(&outcome.findings))
        )];
        lines.push(String::new());
        lines.push("总结".to_string());
        lines.extend(outcome.summary.iter().map(Finding::line));
        lines.push(String::new());
        lines.push("各项".to_string());
        lines.extend(outcome.findings.iter().map(Finding::line));
        if self.env.webrtc.is_none() {
            lines.push("· WebRTC：本平台不检测（没有内置浏览器）".to_string());
        }
        if let Some(words) = &outcome.dns_conclusion {
            lines.push(format!("bash.ws 的结论：{words}"));
        }
        if RealNetworks::parse(&self.settings.real_networks).is_empty() {
            lines.push(
                "提示：关掉代理 / VPN 测一次，把「出口」那行的 ASN 填进设置里的「真实网络」，\
                 才判得出 DNS 是否泄露给了你的运营商"
                    .to_string(),
            );
        }
        lines.push(
            "这里测的是网络层。App 若有定位权限，会直接用 GPS / Wi-Fi 定位，与隧道无关".to_string(),
        );
        Some(lines.join("\n"))
    }
}

impl ToolModule for NetcheckTool {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "网络泄露检测"
    }

    fn menu_items(&self) -> Vec<MenuItem> {
        let mut items = Vec::new();
        match (&self.last, self.running()) {
            (_, true) => items.push(MenuItem::disabled("检测中…")),
            (None, false) => items.push(MenuItem::disabled("还没检测过")),
            (Some(outcome), false) => {
                let ago = short_duration(now_seconds() - outcome.at);
                items.push(MenuItem::disabled(&format!(
                    "{}（{ago}前）",
                    headline(netcheck::overall(&outcome.findings))
                )));
                for finding in &outcome.summary {
                    items.push(MenuItem::disabled(&finding.line()));
                }
                items.push(MenuItem::Separator);
                for finding in &outcome.findings {
                    items.push(MenuItem::disabled(&finding.line()));
                }
            }
        }
        items.push(MenuItem::Separator);
        let mut run = MenuItem::action(RUN, "立即检测");
        if self.running() {
            run = match run {
                MenuItem::Action {
                    id, label, hint, ..
                } => MenuItem::Action {
                    id,
                    label,
                    enabled: false,
                    hint,
                },
                other => other,
            };
        }
        items.push(run);
        if self.last.is_some() {
            items.push(MenuItem::action(REPORT, "完整报告…"));
        }
        items
    }

    fn settings_page(&self) -> Option<SettingsPage> {
        let defaults = Settings::defaults();
        Some(SettingsPage::new(
            ID,
            "网络泄露检测",
            vec![
                Field::text("real_networks", "真实网络（ASN）", "", "如 AS4657, AS9506").with_help(
                    "关掉代理 / VPN 测一次，把「出口」那行的 ASN 填进来（手机热点、家宽各一个）。\
                         出口或 DNS 里出现它们就算泄露",
                ),
                Field::text("api_key", "ipapi.is 的 key", "", "可留空").with_help(
                    "留空也能测，但没有机房 / VPN 判定，只认内置的几家大云厂商。\
                         免费账号每天 1000 次；key 以明文存在配置文件里",
                ),
                Field::number("dns_probes", "DNS 探测解析几个域名", 10, 1, 50),
                Field::text(
                    "ip_endpoint",
                    "IP 归属服务",
                    &defaults.ip_endpoint,
                    &defaults.ip_endpoint,
                ),
                Field::text(
                    "ipv6_endpoint",
                    "IPv6 探测地址",
                    &defaults.ipv6_endpoint,
                    &defaults.ipv6_endpoint,
                )
                .with_help("必须是只有 IPv6 地址的服务：连得上就说明有 IPv6 出口"),
                Field::text(
                    "dns_endpoint",
                    "DNS 泄露检测服务",
                    &defaults.dns_endpoint,
                    &defaults.dns_endpoint,
                ),
                Field::text(
                    "stun_server",
                    "WebRTC 用的 STUN 服务器",
                    &defaults.stun_server,
                    &defaults.stun_server,
                )
                .with_help("只在有内置浏览器的平台上用：网页经它拿到的公网地址应当就是出口 IP"),
            ],
        ))
    }

    fn activate(&mut self, config: &Config) {
        // 不自动测：每次检测都会把出口 IP 告诉第三方服务，只在用户点了才发
        self.settings = Settings::read(config);
    }

    fn config_changed(&mut self, config: &Config) {
        self.settings = Settings::read(config);
    }

    fn tick(&mut self) -> bool {
        let Some(inbox) = &self.inbox else {
            return false;
        };
        match inbox.try_recv() {
            Ok(outcome) => {
                self.last = Some(outcome);
                self.inbox = None;
                true
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => false,
            // 后台线程没发结果就退了（不该发生）：别让菜单永远停在「检测中」
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.inbox = None;
                true
            }
        }
    }

    fn perform(&mut self, action: &str) -> Result<String, String> {
        match action {
            RUN => {
                if self.running() {
                    return Err("上一次检测还没完".to_string());
                }
                self.start();
                Ok("正在检测，结果稍后出现在菜单里".to_string())
            }
            REPORT => self.report_text().ok_or_else(|| "还没检测过".to_string()),
            other => Err(format!("网络泄露检测不认识动作 {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const IPV4: &str = r#"{"ip":"34.3.107.77","is_bogon":false,"company":"Google LLC","asn":"AS15169 Google LLC","city":"The Dalles","region":"Oregon","country":"United States","timezone":"America/Los_Angeles"}"#;
    const IPV6: &str = r#"{"ip":"2406:3003::1","is_bogon":false,"company":"StarHub","asn":"AS4657 Starhub Ltd.","city":"Singapore","region":"","country":"Singapore","timezone":"Asia/Singapore"}"#;
    const DNS: &str = r#"[{"ip":"34.3.107.77","asn":"AS15169 Google LLC","org":"Google LLC","country_name":"USA","type":"ip"},{"ip":"172.253.2.1","asn":"AS15169 Google LLC","org":"Google LLC","country_name":"USA","type":"dns"},{"ip":"DNS is not leaking.","type":"conclusion"}]"#;

    /// 一个只有 IPv4 的网络：IPv6 探测连不上。
    fn ipv4_only(url: &str) -> Result<String, String> {
        if url.starts_with("https://api6.ipify.org") {
            return Err("连不上".to_string());
        }
        if url == "https://bash.ws/id" {
            return Ok("25d1954661847181\n".to_string());
        }
        if url == "https://bash.ws/dnsleak/test/25d1954661847181?json=2" {
            return Ok(DNS.to_string());
        }
        if url == "https://api.ipapi.is/" {
            return Ok(IPV4.to_string());
        }
        Err(format!("测试里没准备 {url}"))
    }

    /// IPv6 绕过了隧道。
    fn ipv6_leaking(url: &str) -> Result<String, String> {
        if url.starts_with("https://api6.ipify.org") {
            return Ok("2406:3003::1".to_string());
        }
        if url == "https://api.ipapi.is/?q=2406:3003::1" {
            return Ok(IPV6.to_string());
        }
        ipv4_only(url)
    }

    /// 带 key 时 URL 要带上 key。
    fn keyed(url: &str) -> Result<String, String> {
        if url == "https://api.ipapi.is/?key=k123" {
            return Ok(IPV4.to_string());
        }
        if url == "https://api.ipapi.is/" {
            return Err("没带 key".to_string());
        }
        ipv4_only(url)
    }

    /// DNS 服务回了个不像 id 的东西。
    fn bad_id(url: &str) -> Result<String, String> {
        if url == "https://bash.ws/id" {
            return Ok("<html>oops</html>".to_string());
        }
        ipv4_only(url)
    }

    fn singapore() -> Option<String> {
        Some("Asia/Singapore".to_string())
    }

    fn no_resolve(_: &str) {}

    fn env(http_get: HttpGet) -> Env {
        Env {
            http_get,
            system_timezone: singapore,
            resolve: no_resolve,
            webrtc: None,
        }
    }

    /// 浏览器经 STUN 拿到了出口 IP。
    fn webrtc_clean(stun: &str) -> Result<Vec<String>, String> {
        assert_eq!(stun, "stun:stun.l.google.com:19302");
        Ok(vec![
            "candidate:1 1 udp 2113937151 abc.local 5000 typ host".to_string(),
            "candidate:2 1 udp 1677729535 34.3.107.77 6000 typ srflx raddr 0.0.0.0 rport 0"
                .to_string(),
        ])
    }

    /// UDP 走了真实网络。
    fn webrtc_leaking(_: &str) -> Result<Vec<String>, String> {
        Ok(vec![
            "candidate:2 1 udp 1677729535 82.66.115.249 6000 typ srflx raddr 0.0.0.0 rport 0"
                .to_string(),
        ])
    }

    fn settings(real: &str) -> Settings {
        Settings {
            real_networks: real.to_string(),
            ..Settings::defaults()
        }
    }

    #[test]
    fn a_full_run_on_an_ipv4_only_network() {
        let observations = run_checks(&settings("4657"), &env(ipv4_only));
        let findings = netcheck::evaluate(&observations, &RealNetworks::parse("4657"));
        assert_eq!(
            findings[0].verdict,
            Verdict::Notice,
            "Google Cloud 出口是机房 IP"
        );
        assert_eq!(
            findings[1].verdict,
            Verdict::Ok,
            "连不上纯 IPv6 = 没有 IPv6 出口"
        );
        assert_eq!(findings[2].verdict, Verdict::Ok);
        assert_eq!(
            findings[3].verdict,
            Verdict::Notice,
            "新加坡系统 + 美国出口"
        );
    }

    #[test]
    fn an_ipv6_exit_on_the_real_network_is_caught() {
        let observations = run_checks(&settings("4657"), &env(ipv6_leaking));
        let findings = netcheck::evaluate(&observations, &RealNetworks::parse("4657"));
        assert_eq!(findings[1].verdict, Verdict::Leak);
        assert!(findings[1].detail.contains("2406:3003::1"));
    }

    #[test]
    fn the_api_key_is_sent_when_configured() {
        let mut with_key = settings("");
        with_key.api_key = "k123".to_string();
        let observations = run_checks(&with_key, &env(keyed));
        assert!(observations.ipv4.is_ok(), "{:?}", observations.ipv4);
    }

    #[test]
    fn a_malformed_test_id_is_refused_before_it_reaches_dns() {
        let observations = run_checks(&settings(""), &env(bad_id));
        assert_eq!(observations.dns, Err("拿到的测试 id 不对".to_string()));
    }

    #[test]
    fn probes_are_resolved_under_the_test_id() {
        use std::sync::Mutex;
        static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn record(host: &str) {
            SEEN.lock().unwrap().push(host.to_string());
        }
        let mut probe = settings("");
        probe.dns_probes = 3;
        let mut test_env = env(ipv4_only);
        test_env.resolve = record;
        let _ = run_checks(&probe, &test_env);
        assert_eq!(
            *SEEN.lock().unwrap(),
            vec![
                "1.25d1954661847181.bash.ws",
                "2.25d1954661847181.bash.ws",
                "3.25d1954661847181.bash.ws"
            ]
        );
    }

    #[test]
    fn settings_fall_back_to_defaults_and_clamp_probes() {
        let config = Config::parse(
            "[netcheck]\nip_endpoint =  \ndns_probes = 500\nreal_networks = AS4657\n",
        );
        let read = Settings::read(&config);
        assert_eq!(
            read.ip_endpoint, "https://api.ipapi.is/",
            "清空的地址按默认值"
        );
        assert_eq!(read.dns_probes, 50);
        assert_eq!(read.real_networks, "AS4657");
    }

    #[test]
    fn query_strings_are_joined_correctly() {
        assert_eq!(with_query("https://a/", ""), "https://a/");
        assert_eq!(with_query("https://a/", "q=1"), "https://a/?q=1");
        assert_eq!(with_query("https://a/?x=1", "q=1"), "https://a/?x=1&q=1");
        assert_eq!(ipapi_query(Some("1.2.3.4"), "k"), "q=1.2.3.4&key=k");
    }

    #[test]
    fn running_from_the_menu_lands_results_in_the_menu() {
        let mut tool = NetcheckTool::with_env(env(ipv4_only));
        tool.config_changed(&Config::parse("[netcheck]\nreal_networks = 4657\n"));
        assert!(
            matches!(&tool.menu_items()[0], MenuItem::Action { label, .. } if label == "还没检测过")
        );
        assert!(tool.perform(RUN).is_ok());
        assert!(tool.running());
        assert!(tool.perform(RUN).is_err(), "跑着的时候不再起第二次");

        let deadline = Instant::now() + Duration::from_secs(5);
        while tool.running() && Instant::now() < deadline {
            tool.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!tool.running());
        let outcome = tool.last().expect("应当有结果");
        assert_eq!(outcome.findings.len(), 4);
        assert_eq!(
            outcome.dns_conclusion.as_deref(),
            Some("DNS is not leaking.")
        );

        let labels: Vec<String> = tool
            .menu_items()
            .into_iter()
            .filter_map(|item| match item {
                MenuItem::Action { label, .. } => Some(label),
                _ => None,
            })
            .collect();
        assert!(labels.iter().any(|l| l.starts_with("! 出口：")));
        assert!(labels.iter().any(|l| l == "完整报告…"));
        assert!(labels.iter().any(|l| l.contains(netcheck::GOAL_CARRIER)));
        let report = tool.perform(REPORT).unwrap();
        assert!(report.contains("bash.ws 的结论：DNS is not leaking."));
        assert!(report.contains("本平台不检测"));
    }

    #[test]
    fn a_platform_webrtc_probe_adds_the_webrtc_check() {
        let mut test_env = env(ipv4_only);
        test_env.webrtc = Some(webrtc_clean);
        let observations = run_checks(&settings("4657"), &test_env);
        let findings = netcheck::evaluate(&observations, &RealNetworks::parse("4657"));
        let webrtc = findings.iter().find(|f| f.check == "WebRTC").unwrap();
        assert_eq!(webrtc.verdict, Verdict::Ok);
        let summary = netcheck::summarize(&observations, &findings);
        assert_eq!(summary[0].verdict, Verdict::Ok);
    }

    #[test]
    fn a_webrtc_leak_reaches_the_summary() {
        let tool = NetcheckTool::with_env(env(ipv4_only)).with_webrtc(webrtc_leaking);
        let observations = run_checks(&settings("4657"), &tool.env);
        let findings = netcheck::evaluate(&observations, &RealNetworks::parse("4657"));
        let summary = netcheck::summarize(&observations, &findings);
        assert_eq!(summary[0].verdict, Verdict::Leak);
        assert_eq!(summary[1].verdict, Verdict::Leak);
        assert!(summary[1].detail.contains("WebRTC"));
    }

    #[test]
    fn unknown_actions_are_refused() {
        let mut tool = NetcheckTool::with_env(env(ipv4_only));
        assert!(tool.perform("netcheck.nope").is_err());
        assert!(tool.perform(REPORT).is_err(), "没测过就没有报告");
    }

    #[test]
    fn every_setting_key_is_declared() {
        // 读的键与设置页声明的键对得上，不然设置窗口改了也不生效
        let tool = NetcheckTool::with_env(env(ipv4_only));
        let page = tool.settings_page().unwrap();
        let declared = crate::settings::declared_keys(&page);
        for key in [
            "real_networks",
            "api_key",
            "dns_probes",
            "ip_endpoint",
            "ipv6_endpoint",
            "dns_endpoint",
            "stun_server",
        ] {
            assert!(declared.contains(&key), "{key} 没在设置页里声明");
        }
    }
}
