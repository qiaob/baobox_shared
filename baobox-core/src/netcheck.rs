//! 网络泄露检测的纯逻辑：解析检测服务的回包、判定有没有泄露、拼成报告。
//!
//! 用来回答一个问题：**开着代理 / VPN / Tailscale 出口节点时，有没有东西绕过了隧道**。
//! 四项检测，各自独立出结论：
//!
//! | 检测 | 看什么 | 什么算泄露 |
//! |---|---|---|
//! | 出口 IP | 当前公网 IPv4 属于谁、在哪、是不是机房 | 出口就是「真实网络」（隧道没生效） |
//! | IPv6 | 有没有 IPv6 出口、它属于谁 | IPv6 走了另一条路（与 IPv4 出口不是同一家） |
//! | DNS | 实际替你查 DNS 的服务器属于谁 | 其中有「真实网络」的服务器 |
//! | 时区 | 系统时区与出口 IP 所在时区 | 不算泄露，但不一致时 App 能看出你在用代理 |
//!
//! 「真实网络」由用户声明：关掉 VPN 跑一次，把显示的 ASN 填进设置（[`RealNetworks`]）。
//! 不声明也能用，只是判不出「泄露给了谁」，只报告看到了什么。
//!
//! 网络请求不在这里：Rust 标准库没有 HTTPS，由平台层提供（见 `baobox-app` 的
//! `netcheck_tool`）。这里只吃回包文本，所以全部能在开发机上测。
//!
//! # 两个检测服务
//!
//! - **ipapi.is**：IP 归属与位置。2026-09-01 起**不带 key 的回包不再有机房 / VPN 判定**
//!   （只剩归属与位置，`asn` 也从对象变成了一个字符串），带 key 的回包才有
//!   `is_datacenter` / `is_vpn` 等字段。两种形状都认（[`parse_ipapi`]）；没有 key 时
//!   机房判定退回内置的一张主要云厂商 ASN 表（[`known_hosting`]）。
//! - **bash.ws**：DNS 泄露。拿一个测试 id，用系统解析器去解析一串带这个 id 的域名，
//!   bash.ws 的权威 DNS 就能记下是谁来问的；再取结果（[`parse_bashws`]）。

use crate::json::{self, Json};

/// 一个 IP 的归属与位置。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IpInfo {
    /// 地址本身
    pub ip: String,
    /// 自治系统号（`AS15169` 里的 15169）。认不出就是 `None`
    pub asn: Option<u32>,
    /// 网络运营方（ASN 的 org，如 `Google LLC`）
    pub network: String,
    /// 地址登记的公司（常与 [`IpInfo::network`] 相同）
    pub company: String,
    /// 城市
    pub city: String,
    /// 国家全名
    pub country: String,
    /// IANA 时区名，如 `Asia/Singapore`
    pub timezone: String,
    /// 是不是机房 / 云主机。带 key 的回包才有；没有就是 `None`
    pub datacenter: Option<bool>,
    /// 是不是已知 VPN 出口。同上
    pub vpn: Option<bool>,
    /// 是不是已知代理。同上
    pub proxy: Option<bool>,
    /// 是不是 Tor 节点。同上
    pub tor: Option<bool>,
}

impl IpInfo {
    /// 给人看的一行：`34.3.107.77（Google LLC，AS15169，The Dalles, United States）`。
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.network.is_empty() {
            parts.push(self.network.clone());
        } else if !self.company.is_empty() {
            parts.push(self.company.clone());
        }
        if let Some(asn) = self.asn {
            parts.push(format!("AS{asn}"));
        }
        let place: Vec<&str> = [self.city.as_str(), self.country.as_str()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        if !place.is_empty() {
            parts.push(place.join(", "));
        }
        if parts.is_empty() {
            self.ip.clone()
        } else {
            format!("{}（{}）", self.ip, parts.join("，"))
        }
    }

    /// 是不是机房 IP：服务给了判定就用判定，没给就查内置的云厂商表。
    ///
    /// 返回 `Some(谁家机房)`。服务判定是机房但认不出是谁家时，用运营方名字代替。
    pub fn hosting(&self) -> Option<String> {
        if self.datacenter == Some(false) {
            return None;
        }
        if let Some(name) = self.asn.and_then(known_hosting) {
            return Some(name.to_string());
        }
        if self.datacenter == Some(true) {
            let name = if self.network.is_empty() {
                &self.company
            } else {
                &self.network
            };
            return Some(if name.is_empty() {
                "未知机房".to_string()
            } else {
                name.clone()
            });
        }
        None
    }
}

/// 从 `AS15169 Google LLC` 这种字符串里拆出号码和名字。
fn split_asn(text: &str) -> (Option<u32>, String) {
    let text = text.trim();
    let Some(rest) = text.strip_prefix("AS").or_else(|| text.strip_prefix("as")) else {
        return (None, text.to_string());
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let name = rest[digits.len()..].trim().to_string();
    (digits.parse().ok(), name)
}

/// 取一个字符串字段，缺失或不是字符串都当空串。
fn text_of(value: Option<&Json>) -> String {
    value.and_then(Json::as_str).unwrap_or("").to_string()
}

/// 取一个布尔字段。缺失 / null / 别的类型都是 `None`。
fn bool_of(value: Option<&Json>) -> Option<bool> {
    match value {
        Some(Json::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// 解析 ipapi.is 的回包。认两种形状：
///
/// - **不带 key**（2026-09-01 起）：`company`、`asn`（`"AS15169 Google LLC"`）、
///   `city`、`region`、`country`、`timezone` 都在顶层，没有 `is_datacenter` 等判定
/// - **带 key**：`company`、`asn`、`location` 是对象，顶层有 `is_datacenter` /
///   `is_vpn` / `is_proxy` / `is_tor`
///
/// 不是 JSON、没有 `ip`、或者是保留地址（`is_bogon`）都返回 `None`。
pub fn parse_ipapi(text: &str) -> Option<IpInfo> {
    let root = json::parse(text)?;
    let ip = root.get("ip")?.as_str()?.to_string();
    if bool_of(root.get("is_bogon")) == Some(true) {
        return None;
    }
    let mut info = IpInfo {
        ip,
        datacenter: bool_of(root.get("is_datacenter")),
        vpn: bool_of(root.get("is_vpn")),
        proxy: bool_of(root.get("is_proxy")),
        tor: bool_of(root.get("is_tor")),
        ..IpInfo::default()
    };

    match root.get("asn") {
        Some(Json::Str(text)) => {
            let (number, name) = split_asn(text);
            info.asn = number;
            info.network = name;
        }
        Some(object @ Json::Object(_)) => {
            info.asn = object
                .get("asn")
                .and_then(Json::as_i64)
                .and_then(|n| u32::try_from(n).ok());
            info.network = text_of(object.get("org"));
        }
        _ => {}
    }

    info.company = match root.get("company") {
        Some(Json::Str(text)) => text.clone(),
        Some(object @ Json::Object(_)) => text_of(object.get("name")),
        _ => String::new(),
    };

    // 位置：带 key 的在 location 里，不带 key 的在顶层
    let place = match root.get("location") {
        Some(location @ Json::Object(_)) => location,
        _ => &root,
    };
    info.city = text_of(place.get("city"));
    info.country = text_of(place.get("country"));
    info.timezone = text_of(place.get("timezone"));
    Some(info)
}

/// 主要云厂商 / 机房的 ASN。没有 ipapi.is 的 key 时，机房判定靠这张表。
///
/// 只收**几乎只做托管**的网络：这些 ASN 下的地址，绝大多数 App 都会当成「数据中心 IP」。
/// 宁缺毋滥 —— 把一家家宽运营商误收进来，就会对普通用户误报。
pub fn known_hosting(asn: u32) -> Option<&'static str> {
    Some(match asn {
        16509 | 14618 => "Amazon AWS",
        15169 | 396982 => "Google Cloud",
        8075 => "Microsoft Azure",
        31898 => "Oracle Cloud",
        14061 => "DigitalOcean",
        20473 => "Vultr",
        63949 => "Akamai / Linode",
        24940 => "Hetzner",
        16276 => "OVHcloud",
        45102 => "阿里云",
        132203 => "腾讯云",
        9009 => "M247",
        60068 => "CDN77 / Datacamp",
        _ => return None,
    })
}

/// 一台 DNS 服务器（或 bash.ws 看到的客户端 IP）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Resolver {
    /// 地址
    pub ip: String,
    /// 自治系统号
    pub asn: Option<u32>,
    /// 运营方
    pub network: String,
    /// 城市
    pub city: String,
    /// 国家
    pub country: String,
}

impl Resolver {
    /// 给人看的一行。
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.network.is_empty() {
            parts.push(self.network.clone());
        }
        if let Some(asn) = self.asn {
            parts.push(format!("AS{asn}"));
        }
        if !self.country.is_empty() {
            parts.push(self.country.clone());
        }
        if parts.is_empty() {
            self.ip.clone()
        } else {
            format!("{}（{}）", self.ip, parts.join("，"))
        }
    }
}

/// bash.ws 的 DNS 泄露检测结果。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DnsResult {
    /// bash.ws 看到的客户端 IP（`type == "ip"`）
    pub clients: Vec<Resolver>,
    /// 实际来查询的 DNS 服务器（`type == "dns"`）
    pub resolvers: Vec<Resolver>,
    /// bash.ws 自己的结论文字（`type == "conclusion"`）
    pub conclusion: Option<String>,
    /// 服务端报的错，比如「No DNS servers found. Try again...」（`type == "error"`）
    pub error: Option<String>,
}

/// 解析 `https://bash.ws/dnsleak/test/<id>?json=2` 的回包。
///
/// 回包是一个数组，每条带 `type`：`ip`（客户端）、`dns`（解析器）、`conclusion`、
/// `error`。`ip` 与 `dns` 两种字段相同：`ip`、`asn`（`"AS15169 Google LLC"`）、
/// `org`、`country_name`、`city_name`。`conclusion` 的文字放在 `ip` 字段里
/// （官方脚本就是这么读的），`error` 的在 `text` 里。认不出的 `type` 跳过。
pub fn parse_bashws(text: &str) -> Option<DnsResult> {
    let root = json::parse(text)?;
    let records = root.as_array()?;
    let mut result = DnsResult::default();
    for record in records {
        let kind = record.get("type").and_then(Json::as_str).unwrap_or("");
        match kind {
            "ip" | "dns" => {
                let (asn, from_asn) = split_asn(&text_of(record.get("asn")));
                let org = text_of(record.get("org"));
                let entry = Resolver {
                    ip: text_of(record.get("ip")),
                    asn,
                    network: if org.is_empty() { from_asn } else { org },
                    city: text_of(record.get("city_name")),
                    country: text_of(record.get("country_name")),
                };
                if kind == "ip" {
                    result.clients.push(entry);
                } else {
                    result.resolvers.push(entry);
                }
            }
            "conclusion" => {
                let words = text_of(record.get("ip"));
                let words = if words.is_empty() {
                    text_of(record.get("text"))
                } else {
                    words
                };
                if !words.is_empty() {
                    result.conclusion = Some(words);
                }
            }
            "error" => {
                let words = text_of(record.get("text"));
                result.error = Some(if words.is_empty() {
                    "bash.ws 报了错，但没说原因".to_string()
                } else {
                    words
                });
            }
            _ => {}
        }
    }
    Some(result)
}

/// 用户声明的「真实网络」：不开 VPN 时出口所在的 ASN（手机运营商、家宽）。
///
/// 检测到这些 ASN 出现在出口或 DNS 里，就说明有东西绕过了隧道。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RealNetworks {
    asns: Vec<u32>,
}

impl RealNetworks {
    /// 从设置里那一格解析：逗号 / 空白分隔，`AS4657` 与 `4657` 都认，认不出的跳过。
    pub fn parse(text: &str) -> Self {
        let asns = text
            .split(|c: char| c == ',' || c == '，' || c.is_whitespace())
            .filter_map(|part| {
                let part = part.trim();
                let digits = part
                    .strip_prefix("AS")
                    .or_else(|| part.strip_prefix("as"))
                    .unwrap_or(part);
                digits.parse().ok()
            })
            .collect();
        Self { asns }
    }

    /// 用户声明过没有。
    pub fn is_empty(&self) -> bool {
        self.asns.is_empty()
    }

    /// 这个 ASN 是不是真实网络。
    pub fn contains(&self, asn: Option<u32>) -> bool {
        asn.is_some_and(|asn| self.asns.contains(&asn))
    }
}

/// 一项检测的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 没问题
    Ok,
    /// 不算泄露，但值得知道（机房 IP、时区不一致）
    Notice,
    /// 泄露了
    Leak,
    /// 测不出来（服务连不上、平台没提供数据）
    Unknown,
}

impl Verdict {
    /// 菜单里放在每一行前面的记号。
    pub fn mark(self) -> &'static str {
        match self {
            Verdict::Ok => "✓",
            Verdict::Notice => "!",
            Verdict::Leak => "✗",
            Verdict::Unknown => "?",
        }
    }
}

/// 一项检测：叫什么、结论、一句话说明。
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// 检测项名字，如「DNS」
    pub check: &'static str,
    /// 结论
    pub verdict: Verdict,
    /// 一句话说明，直接给用户看
    pub detail: String,
}

impl Finding {
    fn new(check: &'static str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            check,
            verdict,
            detail: detail.into(),
        }
    }

    /// 菜单里的一行：`✗ DNS：…`。
    pub fn line(&self) -> String {
        format!("{} {}：{}", self.verdict.mark(), self.check, self.detail)
    }
}

/// 一次检测拿到的全部原料。哪一项没拿到就是 `Err(原因)`。
#[derive(Debug, Clone, PartialEq)]
pub struct Observations {
    /// IPv4 出口
    pub ipv4: Result<IpInfo, String>,
    /// IPv6 出口。`Ok(None)` 表示没有 IPv6 出口（连不上纯 IPv6 的地址）
    pub ipv6: Result<Option<IpInfo>, String>,
    /// DNS 泄露检测
    pub dns: Result<DnsResult, String>,
    /// 系统时区（IANA 名）。平台给不出就是 `None`
    pub system_timezone: Option<String>,
}

/// 出口 IP 那一项。
fn judge_exit(ipv4: &Result<IpInfo, String>, real: &RealNetworks) -> Finding {
    const CHECK: &str = "出口";
    let info = match ipv4 {
        Ok(info) => info,
        Err(why) => return Finding::new(CHECK, Verdict::Unknown, format!("测不出：{why}")),
    };
    if real.contains(info.asn) {
        return Finding::new(
            CHECK,
            Verdict::Leak,
            format!("{} 就是你的真实网络 —— 代理 / VPN 没生效", info.describe()),
        );
    }
    let mut flags = Vec::new();
    if let Some(name) = info.hosting() {
        flags.push(format!("{name} 的机房 IP"));
    }
    if info.vpn == Some(true) {
        flags.push("已知 VPN 出口".to_string());
    }
    if info.proxy == Some(true) {
        flags.push("已知代理".to_string());
    }
    if info.tor == Some(true) {
        flags.push("Tor 节点".to_string());
    }
    if flags.is_empty() {
        Finding::new(CHECK, Verdict::Ok, info.describe())
    } else {
        Finding::new(
            CHECK,
            Verdict::Notice,
            format!(
                "{}；{}，部分 App 会当成代理",
                info.describe(),
                flags.join("、")
            ),
        )
    }
}

/// IPv6 那一项。
fn judge_ipv6(
    ipv6: &Result<Option<IpInfo>, String>,
    ipv4: &Result<IpInfo, String>,
    real: &RealNetworks,
) -> Finding {
    const CHECK: &str = "IPv6";
    let info = match ipv6 {
        Ok(None) => return Finding::new(CHECK, Verdict::Ok, "没有 IPv6 出口，不会从这条路漏"),
        Ok(Some(info)) => info,
        Err(why) => return Finding::new(CHECK, Verdict::Unknown, format!("测不出：{why}")),
    };
    if real.contains(info.asn) {
        return Finding::new(
            CHECK,
            Verdict::Leak,
            format!("{} 是你的真实网络 —— IPv6 绕过了隧道", info.describe()),
        );
    }
    if let Ok(v4) = ipv4 {
        if info.asn.is_some() && v4.asn.is_some() && info.asn != v4.asn {
            return Finding::new(
                CHECK,
                Verdict::Leak,
                format!(
                    "{} 与 IPv4 出口不是同一家 —— IPv6 很可能没走隧道",
                    info.describe()
                ),
            );
        }
    }
    Finding::new(
        CHECK,
        Verdict::Ok,
        format!("{}，与 IPv4 出口一致", info.describe()),
    )
}

/// DNS 那一项。
fn judge_dns(dns: &Result<DnsResult, String>, real: &RealNetworks) -> Finding {
    const CHECK: &str = "DNS";
    let result = match dns {
        Ok(result) => result,
        Err(why) => return Finding::new(CHECK, Verdict::Unknown, format!("测不出：{why}")),
    };
    if let Some(error) = &result.error {
        return Finding::new(CHECK, Verdict::Unknown, format!("bash.ws：{error}"));
    }
    if result.resolvers.is_empty() {
        return Finding::new(
            CHECK,
            Verdict::Unknown,
            "没有看到任何 DNS 服务器来查询，再测一次",
        );
    }
    let leaked: Vec<String> = result
        .resolvers
        .iter()
        .filter(|r| real.contains(r.asn))
        .map(Resolver::describe)
        .collect();
    if !leaked.is_empty() {
        return Finding::new(
            CHECK,
            Verdict::Leak,
            format!("真实网络的 DNS 在替你查询：{}", leaked.join("、")),
        );
    }
    // 按运营方归并，一屏几十台 Google 服务器没有意义
    let mut owners: Vec<String> = Vec::new();
    for resolver in &result.resolvers {
        let name = if resolver.network.is_empty() {
            resolver.ip.clone()
        } else {
            resolver.network.clone()
        };
        if !owners.contains(&name) {
            owners.push(name);
        }
    }
    let mut detail = format!(
        "{} 台服务器，属于 {}",
        result.resolvers.len(),
        owners.join("、")
    );
    if real.is_empty() {
        detail.push_str("（没声明真实网络，判不出是否泄露）");
        return Finding::new(CHECK, Verdict::Unknown, detail);
    }
    Finding::new(CHECK, Verdict::Ok, detail)
}

/// 时区那一项。
fn judge_timezone(system: Option<&str>, ipv4: &Result<IpInfo, String>) -> Finding {
    const CHECK: &str = "时区";
    let Some(system) = system.filter(|s| !s.is_empty()) else {
        return Finding::new(CHECK, Verdict::Unknown, "拿不到系统时区");
    };
    let exit = match ipv4 {
        Ok(info) if !info.timezone.is_empty() => &info.timezone,
        _ => return Finding::new(CHECK, Verdict::Unknown, "不知道出口所在时区"),
    };
    if system == exit {
        Finding::new(CHECK, Verdict::Ok, format!("系统与出口都是 {system}"))
    } else {
        Finding::new(
            CHECK,
            Verdict::Notice,
            format!("系统 {system}，出口 {exit} —— 网页和 App 能据此看出你在用代理"),
        )
    }
}

/// 把原料变成四项结论，顺序固定：出口、IPv6、DNS、时区。
pub fn evaluate(observations: &Observations, real: &RealNetworks) -> Vec<Finding> {
    vec![
        judge_exit(&observations.ipv4, real),
        judge_ipv6(&observations.ipv6, &observations.ipv4, real),
        judge_dns(&observations.dns, real),
        judge_timezone(observations.system_timezone.as_deref(), &observations.ipv4),
    ]
}

/// 整体结论：有泄露就是泄露；否则有测不出的就是测不出；否则有提示就是提示。
pub fn overall(findings: &[Finding]) -> Verdict {
    let has = |v: Verdict| findings.iter().any(|f| f.verdict == v);
    if has(Verdict::Leak) {
        Verdict::Leak
    } else if has(Verdict::Unknown) {
        Verdict::Unknown
    } else if has(Verdict::Notice) {
        Verdict::Notice
    } else {
        Verdict::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 不带 key 的回包（ipapi.is 2026-11 实测，gcp-us 出口节点）
    const ANON_GCP: &str = r#"{"ip":"34.3.107.77","is_bogon":false,"company":"Google LLC","asn":"AS15169 Google LLC","city":"The Dalles","region":"Oregon","country":"United States","lat":45.59456,"lon":-121.17868,"timezone":"America/Los_Angeles","docs":"https://ipapi.is/free-tier.html?ref=api"}"#;

    /// 不带 key 的回包（ipapi.is 文档里的家宽例子）
    const ANON_HOME: &str = r#"{"ip":"82.66.115.249","is_bogon":false,"company":"Proxad / Free SAS","asn":"AS12322 Free SAS","city":"Goven","region":"Brittany","country":"France","lat":48.0063,"lon":-1.84667,"timezone":"Europe/Paris","docs":"https://ipapi.is/free-tier.html?ref=api"}"#;

    /// 带 key 的回包（ipapi.is 文档的例子，删掉了用不到的字段）
    const KEYED: &str = r#"{"ip":"107.174.138.172","rir":"ARIN","is_bogon":false,"is_mobile":false,"is_datacenter":true,"is_tor":true,"is_proxy":false,"is_vpn":false,"datacenter":{"datacenter":"HostPapa"},"company":{"name":"VPS ACE","type":"business"},"asn":{"asn":36352,"org":"HostPapa","type":"hosting"},"location":{"country":"United States","country_code":"US","state":"New York","city":"Buffalo","timezone":"America/New_York","utcoffset":"-04:00"}}"#;

    /// bash.ws 的回包：有客户端、两台解析器、一条结论。字段形状与 2026-11 实测的 `ip` 记录相同
    const BASHWS_OK: &str = r#"[
        {"ip":"203.0.113.7","country":"sg","country_name":"Singapore","asn":"AS16509 Amazon.com, Inc.","org":"Amazon.com, Inc.","region_name":"","city_name":"Singapore","type":"ip"},
        {"ip":"172.253.2.1","country":"sg","country_name":"Singapore","asn":"AS15169 Google LLC","org":"Google LLC","region_name":"","city_name":"Singapore","type":"dns"},
        {"ip":"162.158.1.1","country":"sg","country_name":"Singapore","asn":"AS13335 Cloudflare, Inc.","org":"Cloudflare, Inc.","region_name":"","city_name":"Singapore","type":"dns"},
        {"ip":"DNS is not leaking.","type":"conclusion"}
    ]"#;

    /// bash.ws 的回包：解析器一台都没来（2026-11 实测，客户端 IP 换成了文档地址）
    const BASHWS_NONE: &str = r#"[{"ip":"203.0.113.9","country":"us","country_name":"USA","asn":"AS396982 Google LLC","org":"Google LLC","region_name":"California","city_name":"San Francisco","type":"ip"},{"type":"error","text":"No DNS servers found. Try again..."}]"#;

    fn obs(ipv4: IpInfo) -> Observations {
        Observations {
            ipv4: Ok(ipv4),
            ipv6: Ok(None),
            dns: Ok(parse_bashws(BASHWS_OK).unwrap()),
            system_timezone: Some("Asia/Singapore".to_string()),
        }
    }

    #[test]
    fn the_anonymous_ipapi_shape_is_read() {
        let info = parse_ipapi(ANON_GCP).unwrap();
        assert_eq!(info.ip, "34.3.107.77");
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.network, "Google LLC");
        assert_eq!(info.city, "The Dalles");
        assert_eq!(info.country, "United States");
        assert_eq!(info.timezone, "America/Los_Angeles");
        assert_eq!(info.datacenter, None, "不带 key 的回包没有机房判定");
    }

    #[test]
    fn the_keyed_ipapi_shape_is_read() {
        let info = parse_ipapi(KEYED).unwrap();
        assert_eq!(info.asn, Some(36352));
        assert_eq!(info.network, "HostPapa");
        assert_eq!(info.company, "VPS ACE");
        assert_eq!(info.city, "Buffalo");
        assert_eq!(info.timezone, "America/New_York");
        assert_eq!(info.datacenter, Some(true));
        assert_eq!(info.tor, Some(true));
        assert_eq!(info.vpn, Some(false));
    }

    #[test]
    fn garbage_and_bogons_are_not_an_answer() {
        assert_eq!(parse_ipapi("<html>rate limited</html>"), None);
        assert_eq!(parse_ipapi(r#"{"error":"x"}"#), None);
        assert_eq!(
            parse_ipapi(r#"{"ip":"10.0.0.1","is_bogon":true,"asn":null}"#),
            None
        );
    }

    #[test]
    fn hosting_falls_back_to_the_known_cloud_table_without_a_key() {
        assert_eq!(
            parse_ipapi(ANON_GCP).unwrap().hosting().as_deref(),
            Some("Google Cloud")
        );
        assert_eq!(
            parse_ipapi(ANON_HOME).unwrap().hosting(),
            None,
            "家宽不是机房"
        );
        assert_eq!(
            parse_ipapi(KEYED).unwrap().hosting().as_deref(),
            Some("HostPapa"),
            "表里没有、但服务判定是机房的，用运营方名字"
        );
    }

    #[test]
    fn a_service_verdict_of_not_datacenter_wins_over_the_table() {
        let mut info = parse_ipapi(ANON_GCP).unwrap();
        info.datacenter = Some(false);
        assert_eq!(info.hosting(), None);
    }

    #[test]
    fn bashws_records_are_sorted_by_type() {
        let result = parse_bashws(BASHWS_OK).unwrap();
        assert_eq!(result.clients.len(), 1);
        assert_eq!(result.resolvers.len(), 2);
        assert_eq!(result.resolvers[0].asn, Some(15169));
        assert_eq!(result.resolvers[0].network, "Google LLC");
        assert_eq!(result.conclusion.as_deref(), Some("DNS is not leaking."));
        assert_eq!(result.error, None);
    }

    #[test]
    fn a_bashws_error_is_kept_not_mistaken_for_no_leak() {
        // 实测踩到的：解析器一台都没来，bash.ws 回的是 error，不是「没泄露」
        let result = parse_bashws(BASHWS_NONE).unwrap();
        assert!(result.resolvers.is_empty());
        assert_eq!(
            result.error.as_deref(),
            Some("No DNS servers found. Try again...")
        );
        let finding = judge_dns(&Ok(result), &RealNetworks::parse("4657"));
        assert_eq!(finding.verdict, Verdict::Unknown);
    }

    #[test]
    fn the_v1_bashws_object_shape_is_not_an_answer() {
        assert_eq!(parse_bashws(r#"{"error":"No DNS servers found."}"#), None);
    }

    #[test]
    fn real_networks_accept_both_spellings_and_skip_junk() {
        let real = RealNetworks::parse("AS4657, 9506，as12322  foo");
        assert!(real.contains(Some(4657)));
        assert!(real.contains(Some(9506)));
        assert!(real.contains(Some(12322)));
        assert!(!real.contains(Some(15169)));
        assert!(!real.contains(None));
        assert!(RealNetworks::parse("  ").is_empty());
    }

    #[test]
    fn an_exit_on_the_real_network_means_the_tunnel_is_off() {
        let home = parse_ipapi(ANON_HOME).unwrap();
        let findings = evaluate(&obs(home), &RealNetworks::parse("AS12322"));
        assert_eq!(findings[0].verdict, Verdict::Leak);
        assert_eq!(overall(&findings), Verdict::Leak);
    }

    #[test]
    fn a_cloud_exit_is_a_notice_not_a_leak() {
        let findings = evaluate(
            &obs(parse_ipapi(ANON_GCP).unwrap()),
            &RealNetworks::parse("4657"),
        );
        assert_eq!(findings[0].verdict, Verdict::Notice);
        assert!(findings[0].detail.contains("Google Cloud"));
    }

    #[test]
    fn a_resolver_on_the_real_network_is_a_dns_leak() {
        let mut observations = obs(parse_ipapi(ANON_GCP).unwrap());
        let mut dns = parse_bashws(BASHWS_OK).unwrap();
        dns.resolvers.push(Resolver {
            ip: "203.116.1.78".to_string(),
            asn: Some(4657),
            network: "StarHub".to_string(),
            ..Resolver::default()
        });
        observations.dns = Ok(dns);
        let findings = evaluate(&observations, &RealNetworks::parse("4657"));
        assert_eq!(findings[2].verdict, Verdict::Leak);
        assert!(findings[2].detail.contains("StarHub"));
    }

    #[test]
    fn dns_owners_are_grouped_and_clean_dns_is_ok() {
        let findings = evaluate(
            &obs(parse_ipapi(ANON_GCP).unwrap()),
            &RealNetworks::parse("4657"),
        );
        assert_eq!(findings[2].verdict, Verdict::Ok);
        assert!(findings[2].detail.contains("Google LLC、Cloudflare, Inc."));
    }

    #[test]
    fn without_declared_real_networks_dns_cannot_be_judged() {
        let findings = evaluate(
            &obs(parse_ipapi(ANON_GCP).unwrap()),
            &RealNetworks::default(),
        );
        assert_eq!(findings[2].verdict, Verdict::Unknown);
    }

    #[test]
    fn an_ipv6_exit_from_another_network_is_a_leak() {
        let mut observations = obs(parse_ipapi(ANON_GCP).unwrap());
        observations.ipv6 = Ok(Some(IpInfo {
            ip: "2406:3003::1".to_string(),
            asn: Some(4657),
            network: "StarHub".to_string(),
            ..IpInfo::default()
        }));
        // 没声明真实网络也能判：与 IPv4 出口不是同一家
        let findings = evaluate(&observations, &RealNetworks::default());
        assert_eq!(findings[1].verdict, Verdict::Leak);
    }

    #[test]
    fn no_ipv6_exit_is_fine() {
        let findings = evaluate(
            &obs(parse_ipapi(ANON_GCP).unwrap()),
            &RealNetworks::default(),
        );
        assert_eq!(findings[1].verdict, Verdict::Ok);
    }

    #[test]
    fn a_timezone_mismatch_is_a_notice() {
        let findings = evaluate(
            &obs(parse_ipapi(ANON_GCP).unwrap()),
            &RealNetworks::default(),
        );
        assert_eq!(findings[3].verdict, Verdict::Notice);
        assert!(findings[3].detail.contains("America/Los_Angeles"));
        let mut observations = obs(parse_ipapi(ANON_GCP).unwrap());
        observations.system_timezone = Some("America/Los_Angeles".to_string());
        assert_eq!(
            evaluate(&observations, &RealNetworks::default())[3].verdict,
            Verdict::Ok
        );
    }

    #[test]
    fn failures_are_reported_as_unknown_with_the_reason() {
        let observations = Observations {
            ipv4: Err("连不上 api.ipapi.is".to_string()),
            ipv6: Err("超时".to_string()),
            dns: Err("拿不到测试 id".to_string()),
            system_timezone: None,
        };
        let findings = evaluate(&observations, &RealNetworks::default());
        assert!(findings.iter().all(|f| f.verdict == Verdict::Unknown));
        assert!(findings[0].detail.contains("api.ipapi.is"));
        assert_eq!(overall(&findings), Verdict::Unknown);
    }

    #[test]
    fn overall_prefers_leak_then_unknown_then_notice() {
        let f = |v| Finding::new("x", v, "");
        assert_eq!(
            overall(&[f(Verdict::Ok), f(Verdict::Notice)]),
            Verdict::Notice
        );
        assert_eq!(
            overall(&[f(Verdict::Notice), f(Verdict::Unknown)]),
            Verdict::Unknown
        );
        assert_eq!(
            overall(&[f(Verdict::Unknown), f(Verdict::Leak)]),
            Verdict::Leak
        );
        assert_eq!(overall(&[f(Verdict::Ok)]), Verdict::Ok);
    }
}
