use std::collections::HashMap;
use std::io::Read;

use ini::Ini;

use crate::networks::Network;
use crate::networks::PSKSecurity;
use crate::networks::Security;

#[derive(Debug)]
pub enum ConversionError {
    ParseError(String),
    NotWireless,
    MissingKeys,
    MissingSSID,
    Unsupported,
    OSError,
}

impl From<ini::ini::Error> for ConversionError {
    fn from(ini_error: ini::ini::Error) -> Self {
        ConversionError::ParseError(ini_error.to_string())
    }
}

/// Get a string according to the netctl quoting rules.
///
/// See man netctl.profile, "SPECIAL QUOTING RULES" for definition.
///
/// # Arguments
///
/// * `config` the ini file to read from.
/// * `key` the key to read from the config
///
/// # Return value
///
///
/// Returns a
fn get_quoted_string<'a>(config: &'a HashMap<String, String>, key: &str) -> Result<(&'a str, bool), ConversionError> {
    if let Some(contents) = config.get(key) {
        let quoted = contents.chars().next() != Some('"');
        if quoted {
            Ok((contents.as_str(), true))
        } else {
            Ok((&contents[1..], false))
        }
    } else {
        Err(ConversionError::MissingKeys)
    }
}

pub fn parse_network(input: &mut impl Read) -> Result<Network, ConversionError> {
    let contents = Ini::read_from(input)?;
    let contents = contents.general_section();

    if contents.get("Connection").map_or("invalid", |s| s.as_str()) != "wireless" {
        return Err(ConversionError::NotWireless);
    }

    let security = match contents.get("Security").map_or("none", |s| s.as_str()) {
        "none" => Security::Open,
        "wpa" => {
            let (key, quoted) = get_quoted_string(contents, "Key")?;
            let passphrase = if quoted {
                PSKSecurity::Password(key.to_owned())
            } else {
                PSKSecurity::PSK(key.to_owned())
            };
            Security::PSK(passphrase)
        }
        _ => return Err(ConversionError::Unsupported)
    };

    if let Some(ssid) = contents.get("ESSID") {
        Ok(Network::new(ssid.to_owned(), security))
    } else {
        Err(ConversionError::MissingSSID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_quoted_string() {
        let sample = b"quoted=quoted_value\nnon_quoted=\\\"non_quoted_value\n";
        let ini = Ini::read_from(&mut sample.as_ref()).unwrap();
        let contents = ini.general_section();

        let (value, quoted) = get_quoted_string(contents, "quoted").unwrap();
        assert_eq!("quoted_value", value);
        assert!(quoted);

        let (value, quoted) = get_quoted_string(contents, "non_quoted").unwrap();
        assert_eq!("non_quoted_value", value);
        assert!(!quoted);
    }

    #[test]
    fn test_parse_network() {
        let sample = b"Connection=wireless\nESSID=foo_network\nKey=foo_password\nSecurity=wpa";
        let network = parse_network(&mut sample.as_ref()).unwrap();

        let correct_network = Network::new("foo_network".to_string(),
                                           Security::PSK(PSKSecurity::Password("foo_password".to_string())));

        assert_eq!(correct_network, network);
    }
}