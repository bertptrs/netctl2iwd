use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

use std::ffi::OsString;

pub enum PSKSecurity {
    Password(String),
    PSK(String),
}

pub enum Security {
    Open,
    PSK(PSKSecurity),
}

impl Security {
    fn get_extension(&self) -> &str {
        match self {
            Security::Open => ".open",
            Security::PSK(_) => ".psk",
        }
    }
}

pub struct Network {
    ssid: String,
    security: Security,
}

impl Network {
    /// Compute the filename (not the dir) for this file.
    ///
    /// This function is based on storage_get_network_file_path in the iwd source code.
    pub fn iwd_file_name(&self) -> OsString {
        let mut name = if self.name_is_safe() {
            self.ssid.clone()
        } else {
            let mut buf = String::from("=");
            buf += &hex::encode(self.ssid.as_bytes());
            buf
        };

        name += self.security.get_extension();

        OsString::from(name)
    }

    fn name_is_safe(&self) -> bool {
        self.ssid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }
}

pub fn compute_psk(ssid: &[u8], passphrase: &[u8]) -> [u8; 32] {
    let mut buffer = [0u8; 32];

    pbkdf2::<Hmac<Sha1>>(passphrase, ssid, 4096, &mut buffer);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_psk() {
        let result = compute_psk(b"foonetwork", b"foopassphrase");
        let correct = "843446d8b163207e094b45be552f7180663daa729126778633dbc22ce2ebd1ad";
        let result_hex = hex::encode(result);
        assert_eq!(correct, result_hex);
    }

    #[test]
    fn test_iwd_file_name() {
        let network = Network {
            ssid: "Leiden University".to_string(),
            security: Security::Open,
        };
        assert_eq!(OsString::from("=4c656964656e20556e6976657273697479.open"), network.iwd_file_name());

        let network = Network {
            ssid: "foo_network".to_string(),
            security: Security::PSK(PSKSecurity::Password("bar_password".to_string())),
        };
        assert_eq!(OsString::from("foo_network.psk"), network.iwd_file_name())
    }
}
