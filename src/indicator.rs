use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndicatorType {
    Ip,
    Domain,
    Url,
    Sha256,
    Cve,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Indicator {
    pub value: String,
    pub kind: IndicatorType,
}

#[derive(Error, Debug)]
pub enum IndicatorError {
    #[error("invalid indicator format")]
    InvalidFormat,
}

impl Indicator {
    pub fn new(value: &str, kind: IndicatorType) -> Self {
        Self {
            value: value.to_string(),
            kind,
        }
    }

    pub fn parse_ip(value: &str) -> Result<Self, IndicatorError> {
        if IpAddr::from_str(value).is_ok() {
            Ok(Self::new(value, IndicatorType::Ip))
        } else {
            Err(IndicatorError::InvalidFormat)
        }
    }

    pub fn parse_domain(value: &str) -> Result<Self, IndicatorError> {
        let domain = value.trim();
        let domain_regex = Regex::new(r"^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)$")
            .expect("invalid regex");
        if domain_regex.is_match(domain) {
            Ok(Self::new(domain, IndicatorType::Domain))
        } else {
            Err(IndicatorError::InvalidFormat)
        }
    }

    pub fn parse_url(value: &str) -> Result<Self, IndicatorError> {
        Url::parse(value)
            .map_err(|_| IndicatorError::InvalidFormat)
            .map(|_| Self::new(value, IndicatorType::Url))
    }

    pub fn parse_sha256(value: &str) -> Result<Self, IndicatorError> {
        let normalized = value.trim();
        let hash_regex = Regex::new(r"^[0-9a-fA-F]{64}$").expect("invalid regex");
        if hash_regex.is_match(normalized) {
            Ok(Self::new(normalized, IndicatorType::Sha256))
        } else {
            Err(IndicatorError::InvalidFormat)
        }
    }

    pub fn parse_cve(value: &str) -> Result<Self, IndicatorError> {
        let normalized = value.trim().to_uppercase();
        let cve_regex = Regex::new(r"^(?i:CVE)-\d{4}-\d{4,}$").expect("invalid regex");
        if cve_regex.is_match(&normalized) {
            Ok(Self::new(&normalized, IndicatorType::Cve))
        } else {
            Err(IndicatorError::InvalidFormat)
        }
    }

    pub fn from_guess(value: &str) -> Result<Self, IndicatorError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(IndicatorError::InvalidFormat);
        }

        if Self::parse_ip(trimmed).is_ok() {
            return Self::parse_ip(trimmed);
        }

        if Self::parse_cve(trimmed).is_ok() {
            return Self::parse_cve(trimmed);
        }

        if Self::parse_sha256(trimmed).is_ok() {
            return Self::parse_sha256(trimmed);
        }

        if Self::parse_url(trimmed).is_ok() {
            return Self::parse_url(trimmed);
        }

        if Self::parse_domain(trimmed).is_ok() {
            return Self::parse_domain(trimmed);
        }

        Err(IndicatorError::InvalidFormat)
    }
}
