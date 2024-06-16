use digest::crypto_common::KeyInit;
use digest::FixedOutput;
use digest::Update;
use hex_literal::hex;

use nh::Nh;

#[test]
fn nh_test() {
    let key: &[u8; 1024] = &[b'a'; 1024];

    let mut h = Nh::new(key.into());
    let data = [0; 100];
    digest::Update::update(&mut h, &data[..]);
}

#[test]
fn nh_test2() {
    let key: &[u8; 1024] = &[b'a'; 1024];
    let data = [0; 100];
    let mut h = Nh::new(key.into());
    h.update(&data);
    assert_eq!(h.finalize_fixed().as_slice(), &hex!("049b32ca59c32b94")[..]);
}
