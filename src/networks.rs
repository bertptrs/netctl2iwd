use hmac::Hmac;
use ini::Ini;
use pbkdf2::pbkdf2;
use sha1::Sha1;

#[derive(Eq, PartialEq, Debug)]
pub enum PSKSecurity {
    Password(String),
    PSK(String),
}

#[derive(Eq, PartialEq, Debug)]
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

#[derive(Eq, PartialEq, Debug)]
pub struct Network {
    ssid: String,
    security: Security,
}

fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-_ ".contains(c)
}

impl Network {
    pub fn new(ssid: String, security: Security) -> Network {
        Network {
            ssid,
            security,
        }
    }

    /// Compute the filename (not the dir) for this file.
    ///
    /// This function is based on storage_get_network_file_path in the iwd source code.
    pub fn iwd_file_name(&self) -> String {
        let mut name = if self.ssid.chars().all(is_safe_char) {
            self.ssid.clone()
        } else {
            let mut buf = String::from("=");
            buf += &hex::encode(self.ssid.as_bytes());
            buf
        };

        name += self.security.get_extension();

        name
    }

    pub fn write_config(&self, config: &mut Ini) {
        match &self.security {
            Security::Open => {}

            Security::PSK(security) => {
                let mut section = config.with_section(Some("Security".to_owned()));

                match &security {
                    PSKSecurity::PSK(psk) => section.set("PreSharedKey", psk.to_owned()),
                    PSKSecurity::Password(passphrase) => {
                        let psk = compute_psk(self.ssid.as_bytes(), passphrase.as_bytes());
                        section.set("Passphrase", passphrase.to_owned())
                            .set("PreSharedKey", hex::encode(&psk))
                    }
                };
            }
        };
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

    const FOO_PASSWORD: &str = "bar_password";
    const FOO_PSK: &str = "90b193aaec1446630aeb1d1c24191f580e03e3e4d592b5b682b157a04fa26956";

    fn foo_network() -> Network {
        Network::new("foo_network".to_owned(),
                     Security::PSK(PSKSecurity::Password(FOO_PASSWORD.to_owned())))
    }

    #[test]
    fn test_compute_psk() {
        let result = compute_psk(b"foo_network", FOO_PASSWORD.as_bytes());
        let result_hex = hex::encode(result);
        assert_eq!(FOO_PSK, result_hex);
    }

    #[test]
    fn test_iwd_file_name() {
        let network = Network {
            ssid: "Leiden University".to_string(),
            security: Security::Open,
        };
        assert_eq!("Leiden University.open", network.iwd_file_name());
        assert_eq!("foo_network.psk", foo_network().iwd_file_name());
        let network = Network {
            ssid: "With illegal characters?".to_string(),
            security: Security::Open,
        };
        assert_eq!("=5769746820696c6c6567616c20636861726163746572733f.open", network.iwd_file_name());
    }

    #[test]
    fn test_write_config() {
        let mut config = Ini::new();
        foo_network().write_config(&mut config);
        assert_eq!(config.get_from(Some("Security"), "Passphrase"), Some(FOO_PASSWORD));
        assert_eq!(config.get_from(Some("Security"), "PreSharedKey"), Some(FOO_PSK));
    }
}
