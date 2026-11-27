//! Frozen wire outputs from the pre-sharing HTTP auth code using a fixed public test seed.
use hyp_crypto::Ed25519KeyPair;
use hyp_crypto::http_auth::{http_auth_signing_input, sign_http_auth};

#[test]
fn frozen_http_auth_wire_vectors() {
    let fixture_key = Ed25519KeyPair::from_seed([7; 32]).unwrap();
    assert!(http_auth_signing_input("POST", "/v1/drops?x=%2F", 1700000000000, "000102030405060708090a0b", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "POST\n/v1/drops?x=%2F\n1700000000000\n000102030405060708090a0b\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".as_bytes(), "wire transcript vector 0");
    assert!(
        sign_http_auth(
            "fixture@host",
            &fixture_key,
            "POST",
            "/v1/drops?x=%2F",
            1700000000000,
            "000102030405060708090a0b",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "Hyphae-Ed25519 node=\"fixture@host\",ts=\"1700000000000\",nonce=\"000102030405060708090a0b\",sig=\"xjfsz7jm8rZCmy5DLVX5s2ZGeGWBl77euCsLkMbqtNE3QAjM44nKv-r7U8AqLlJq7IzOSXu58e3zCm4jEY3vDw\"",
        "wire header vector 0"
    );
    assert!(http_auth_signing_input("get", "/a%2fb?z=2&z=1", -1, "00000000-0000-4000-8000-000000000001", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "get\n/a%2fb?z=2&z=1\n-1\n00000000-0000-4000-8000-000000000001\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".as_bytes(), "wire transcript vector 1");
    assert!(
        sign_http_auth(
            "fixture-raw@host",
            &fixture_key,
            "get",
            "/a%2fb?z=2&z=1",
            -1,
            "00000000-0000-4000-8000-000000000001",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "Hyphae-Ed25519 node=\"fixture-raw@host\",ts=\"-1\",nonce=\"00000000-0000-4000-8000-000000000001\",sig=\"2yLcciafB8_iuQvqB81_FYXyQP65qAZojByn6vvfFRnwTrkXkgJ893AdJEWInx-zs54Psl3dQJpj1pNXipf_Cg\"",
        "wire header vector 1"
    );
}
