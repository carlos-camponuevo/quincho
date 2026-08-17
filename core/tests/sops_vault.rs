use quincho_core::sops::{self, Identity};
use quincho_core::vault::MemFs;
use zeroize::Zeroizing;

const KEY: &str = include_str!("test.age.key");
const FIXTURE: &[u8] = include_bytes!("fixture.env.sops");

fn id() -> Identity {
    Identity::from_keys_file(Zeroizing::new(KEY.to_string())).unwrap()
}

#[test]
fn recipients_are_readable_without_a_key() {
    let r = sops::recipients(FIXTURE).unwrap();
    assert_eq!(r, vec![id().public_key().to_string()]);
    assert!(sops::looks_sops(FIXTURE));
    assert!(!sops::looks_sops(b"DB_URL=x"));
}

#[test]
fn decrypts_a_file_written_by_the_sops_cli() {
    let plain = sops::decrypt(FIXTURE, &id()).unwrap();
    assert_eq!(&plain[..], b"DB_URL=postgres://u:p@h/db\nsecret=forge\n");
}

#[test]
fn wrong_identity_is_refused_and_tampering_is_detected() {
    use age::secrecy::ExposeSecret;
    let other = Identity::parse(Zeroizing::new(
        age::x25519::Identity::generate().to_string().expose_secret().to_string(),
    ))
    .unwrap();
    let err = sops::decrypt(FIXTURE, &other).unwrap_err().to_string();
    assert!(err.contains("cannot open"), "{err}");
    // flip one byte inside the payload
    let mut s = String::from_utf8(FIXTURE.to_vec()).unwrap();
    let i = s.find("data:").unwrap() + 8;
    let c = if &s[i..i + 1] == "A" { "B" } else { "A" };
    s.replace_range(i..i + 1, c);
    assert!(sops::decrypt(s.as_bytes(), &id()).is_err());
}

#[test]
fn memfs_decrypts_sops_entries_in_place() {
    let mut fs = MemFs::default();
    fs.files.insert("rouat/conf/var.env.sops".into(), FIXTURE.to_vec());
    fs.files.insert("README.md".into(), b"hi".to_vec());
    assert_eq!(fs.sops_recipients(), vec![id().public_key().to_string()]);
    assert_eq!(fs.decrypt_sops(&id()).unwrap(), 1);
    assert!(fs.get("rouat/conf/var.env").is_some());
    assert!(fs.get("rouat/conf/var.env.sops").is_none());
}
