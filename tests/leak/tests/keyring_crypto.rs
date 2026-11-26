// Exercise the actual patched crypto code on every host, without a D-Bus session.
#[path = "../../../vendor/dbus-secret-service/src/crypto_openssl.rs"]
mod crypto;

#[test]
fn secret_service_rejects_malformed_iv_and_roundtrips_synthetic_canary() {
    let alice = crypto::Keypair::generate().unwrap();
    let bob = crypto::Keypair::generate().unwrap();
    let alice_key = zeroize::Zeroizing::new(alice.derive_shared(&bob.public).unwrap());
    let bob_key = zeroize::Zeroizing::new(bob.derive_shared(&alice.public).unwrap());
    assert_eq!(*alice_key, *bob_key);
    let canary = b"NW_SYNTHETIC_KEYRING_CANARY_0109";
    let (ciphertext, iv) = crypto::encrypt(canary, &alice_key).unwrap();
    assert!(
        !ciphertext
            .windows(canary.len())
            .any(|window| window == canary)
    );
    let clear = zeroize::Zeroizing::new(crypto::decrypt(&ciphertext, &bob_key, &iv).unwrap());
    assert_eq!(&clear[..], canary);
    for length in [0, 1, 15, 17, 32, 128] {
        assert!(crypto::decrypt(&ciphertext, &bob_key, &vec![0; length]).is_err());
    }
    assert!(crypto::decrypt(&[], &bob_key, &iv).is_err());
    assert!(crypto::decrypt(&ciphertext[..ciphertext.len() - 1], &bob_key, &iv).is_err());
    let mut tampered = ciphertext.clone();
    let index = tampered.len() - 17;
    tampered[index] ^= (16 - canary.len() % 16) as u8; // Last padding byte becomes zero.
    assert!(crypto::decrypt(&tampered, &bob_key, &iv).is_err());
    let (empty, empty_iv) = crypto::encrypt(&[], &alice_key).unwrap();
    assert!(
        crypto::decrypt(&empty, &bob_key, &empty_iv)
            .unwrap()
            .is_empty()
    );
    for peer in [&[][..], &[0][..], &[1][..], &[0xff; 129][..]] {
        assert!(alice.derive_shared(peer).is_err());
    }
}
