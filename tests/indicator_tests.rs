use ioccheck::indicator::{Indicator, IndicatorType};

#[test]
fn parse_ip() {
    let indicator = Indicator::parse_ip("8.8.8.8").unwrap();
    assert_eq!(indicator.kind, IndicatorType::Ip);
}

#[test]
fn parse_ipv6() {
    let indicator = Indicator::parse_ip("2001:4860:4860::8888").unwrap();
    assert_eq!(indicator.kind, IndicatorType::Ip);
}

#[test]
fn parse_domain() {
    let indicator = Indicator::parse_domain("example.com").unwrap();
    assert_eq!(indicator.kind, IndicatorType::Domain);
}

#[test]
fn parse_url() {
    let indicator = Indicator::parse_url("https://example.com/login").unwrap();
    assert_eq!(indicator.kind, IndicatorType::Url);
}

#[test]
fn parse_sha256() {
    let input = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let indicator = Indicator::parse_sha256(input).unwrap();
    assert_eq!(indicator.kind, IndicatorType::Sha256);
}

#[test]
fn parse_cve() {
    let indicator = Indicator::parse_cve("CVE-2024-3094").unwrap();
    assert_eq!(indicator.kind, IndicatorType::Cve);
}

#[test]
fn guess_detection() {
    let indicator = Indicator::from_guess("example.com").unwrap();
    assert_eq!(indicator.kind, IndicatorType::Domain);
}
