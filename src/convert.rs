use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::File;
use std::fs::OpenOptions;
use std::fs::Permissions;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ParseError;

use ini::Ini;

use crate::networks::Network;
use crate::networks::PSKSecurity;
use crate::networks::Security;
use std::fmt;

pub enum ConversionError {
    ParseError(String),
    NotWireless,
    MissingKeys,
    MissingSSID,
    Unsupported,
    PermissionDenied,
    FileExists,
    OSError,
}

impl Display for ConversionError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        use self::ConversionError::*;

        match self {
            ParseError(value) => write!(f, "Unable to parse profile: {}", value),
            NotWireless => write!(f, "Not a wireless profile"),
            MissingKeys => write!(f, "Key information missing"),
            MissingSSID => write!(f, "SSID missing"),
            Unsupported => write!(f, "Unsupported security type"),
            PermissionDenied => write!(f, "Unable to open file"),
            FileExists => write!(f, "File exists, refusing to overwrite"),
            OSError => write!(f, "Unknown error"),
        }
    }
}

impl From<ini::ini::Error> for ConversionError {
    fn from(ini_error: ini::ini::Error) -> Self {
        ConversionError::ParseError(ini_error.to_string())
    }
}

impl From<io::Error> for ConversionError {
    fn from(io_error: io::Error) -> Self {
        match io_error.kind() {
            ErrorKind::PermissionDenied => ConversionError::PermissionDenied,
            ErrorKind::AlreadyExists => ConversionError::FileExists,
            _ => ConversionError::OSError,
        }
    }
}

impl From<ParseError> for ConversionError {
    fn from(_: ParseError) -> Self {
        ConversionError::OSError
    }
}

pub fn convert_files<'a>(input: impl Iterator<Item=&'a str>, output_dir: &str) {
    for file in input {
        match convert(file, output_dir) {
            Ok(_) => println!("Successfully converted {}", file),
            Err(error) => println!("Failed to convert {}: {}", file, error),
        }
    }
}

fn convert(input: &str, output_dir: &str) -> Result<(), ConversionError> {
    let mut input = File::open(input)?;
    let network = parse_network(&mut input)?;

    let mut output_path = PathBuf::from_str(output_dir)?;
    output_path.push(network.iwd_file_name());

    let mut config = Ini::new();
    network.write_config(&mut config);

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path.as_path())?;
    output.set_permissions(Permissions::from_mode(0o600))?;
    config.write_to(&mut output)?;

    Ok(())
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