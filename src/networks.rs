use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;

pub fn compute_psk(ssid: &[u8], passphrase: &[u8]) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    let mut mac = Hmac::new(Sha1::new(), passphrase);

    pbkdf2(&mut mac, ssid, 4096, &mut buffer);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_psk() {
        let result = compute_psk(b"foonetwork", b"foopassphrase");
        let correct = "843446d8b163207e094b45be552f7180663daa729126778633dbc22ce2ebd1ad";
        let result_hex = result.iter().map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>().join("");
        assert_eq!(correct, result_hex);
    }
}
