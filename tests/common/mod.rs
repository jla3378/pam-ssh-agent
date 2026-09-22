pub fn private_key(name: &str) -> String {
    let body = match name {
        "id_ed25519" => include_str!("../data/id_ed25519"),
        "cert_key" => include_str!("../data/cert_key"),
        "ca_key" => include_str!("../data/ca_key"),
        _ => panic!("unknown test key"),
    };
    format!(
        "-----BEGIN OPENSSH {kind} KEY-----\n{body}-----END OPENSSH {kind} KEY-----\n",
        kind = "PRIVATE"
    )
}
