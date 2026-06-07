pub mod abuseipdb;
pub mod cisa_kev;
pub mod malwarebazaar;
pub mod nvd;
pub mod otx;
pub mod threatfox;
pub mod urlhaus;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

pub(crate) fn deserialize_optional_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        Value::Null => Ok(None),
        Value::String(value) => {
            let values = value
                .split(',')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            Ok(Some(values))
        }
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(value) => Ok(value),
                other => Err(serde::de::Error::custom(format!(
                    "expected tag string, got {other}"
                ))),
            })
            .collect::<Result<Vec<_>, D::Error>>()
            .map(Some),
        other => Err(serde::de::Error::custom(format!(
            "expected string or array for tags, got {other}"
        ))),
    }
}

pub(crate) fn deserialize_optional_u8<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        Value::Null => Ok(None),
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| serde::de::Error::custom("expected confidence level from 0 to 255"))
            .map(Some),
        Value::String(value) => value
            .trim_end_matches('%')
            .parse::<u8>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        other => Err(serde::de::Error::custom(format!(
            "expected number or string for confidence level, got {other}"
        ))),
    }
}
