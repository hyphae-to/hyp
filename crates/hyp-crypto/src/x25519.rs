//! Constant-time RFC 7748 X25519 scalar multiplication with zeroized temporaries.
//!
//! `ring::agreement::X25519` intentionally only supports one-shot random ephemeral keys
//! and does not expose static X25519 private key import or deterministic key derivation
//! required for persistent Hyphae identity keys, RFC 9180 HPKE `Decap`/`DeriveKeyPair`,
//! and v1 `seal`/`open` interoperability.
//!
//! This module implements the exact TweetNaCl constant-time Curve25519 Montgomery ladder
//! over GF(2^255 - 19) using 16-bit limbs in `i64`, with zero secret-dependent branches,
//! explicit `Zeroize` of all intermediate field elements, and constant-time all-zero
//! shared secret rejection (RFC 7748 §6.1).

use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

type Gf = [i64; 16];

/// Basepoint u = 9 for Curve25519 (RFC 7748 §5).
const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Constant `(A - 2) / 4 = 121665 = 0x1db41` in 16-bit little-endian limbs.
const A24: Gf = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Known low-order Curve25519 u-coordinates (including non-canonical encodings mod p)
/// that must be rejected up front as public keys.
const LOW_ORDER_X25519_POINTS: [[u8; 32]; 7] = [
    // 0 (order 4)
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 1 (order 2)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2 on twist)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (equivalent to 0 mod p)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (equivalent to 1 mod p)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Returns `true` if `point` encodes a known low-order Curve25519 u-coordinate (ignoring bit 255).
pub(crate) fn is_low_order_x25519_point(point: &[u8; 32]) -> bool {
    let mut masked = *point;
    masked[31] &= 0x7f;
    let mut hit = 0u8;
    for candidate in &LOW_ORDER_X25519_POINTS {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= masked[i] ^ candidate[i];
        }
        // diff == 0 => matched
        let is_eq = ((diff as u16).wrapping_sub(1) >> 8) as u8 & 1;
        hit |= is_eq;
    }
    hit != 0
}

/// Computes the X25519 public key `X25519(scalar, 9)`.
pub(crate) fn x25519_public_from_private(scalar: &[u8; 32]) -> [u8; 32] {
    let out = scalarmult_raw(scalar, &BASEPOINT);
    *out
}

/// Computes X25519 Diffie-Hellman `X25519(scalar, peer_public)` and fails closed if
/// the peer public key is low-order or the resulting shared secret is all zeros.
pub(crate) fn x25519_dh(
    scalar: &[u8; 32],
    peer_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if is_low_order_x25519_point(peer_public) {
        return Err(CryptoError::SmallOrderKey);
    }
    let shared = scalarmult_raw(scalar, peer_public);
    let mut or_acc = 0u8;
    for &b in shared.iter() {
        or_acc |= b;
    }
    if or_acc == 0 {
        return Err(CryptoError::SmallOrderKey);
    }
    Ok(shared)
}

#[inline]
fn unpack25519(o: &mut Gf, n: &[u8; 32]) {
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
}

#[inline]
fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

#[inline]
fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(o: &mut [u8; 32], n: &Gf) {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
    t.zeroize();
    m.zeroize();
}

#[inline]
fn gf_add(o: &mut Gf, a: &Gf, b: &Gf) {
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
}

#[inline]
fn gf_sub(o: &mut Gf, a: &Gf, b: &Gf) {
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
}

fn gf_mul(o: &mut Gf, a: &Gf, b: &Gf) {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    o.copy_from_slice(&t[..16]);
    car25519(o);
    car25519(o);
    t.zeroize();
}

#[inline]
fn gf_sq(o: &mut Gf, a: &Gf) {
    gf_mul(o, a, a);
}

fn inv25519(o: &mut Gf, i: &Gf) {
    let mut c = *i;
    for a in (0..=253).rev() {
        let prev = c;
        gf_sq(&mut c, &prev);
        if a != 2 && a != 4 {
            let prev = c;
            gf_mul(&mut c, &prev, i);
        }
    }
    *o = c;
    c.zeroize();
}

fn scalarmult_raw(scalar: &[u8; 32], point: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut z = Zeroizing::new(*scalar);
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    let mut x = [0i64; 16];
    unpack25519(&mut x, point);

    let mut a = [0i64; 16];
    let mut b = x;
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    let mut e = [0i64; 16];
    let mut f = [0i64; 16];
    a[0] = 1;
    d[0] = 1;

    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);

        gf_add(&mut e, &a, &c);
        let a_prev = a;
        gf_sub(&mut a, &a_prev, &c);
        gf_add(&mut c, &b, &d);
        let b_prev = b;
        gf_sub(&mut b, &b_prev, &d);

        gf_sq(&mut d, &e);
        gf_sq(&mut f, &a);
        let a_prev = a;
        gf_mul(&mut a, &c, &a_prev);
        gf_mul(&mut c, &b, &e);
        gf_add(&mut e, &a, &c);
        let a_prev = a;
        gf_sub(&mut a, &a_prev, &c);

        gf_sq(&mut b, &a);
        gf_sub(&mut c, &d, &f);
        gf_mul(&mut a, &c, &A24);
        let a_prev = a;
        gf_add(&mut a, &a_prev, &d);
        let c_prev = c;
        gf_mul(&mut c, &c_prev, &a);
        gf_mul(&mut a, &d, &f);
        gf_mul(&mut d, &b, &x);
        gf_sq(&mut b, &e);

        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
    }

    let mut c_inv = [0i64; 16];
    inv25519(&mut c_inv, &c);
    let mut res = [0i64; 16];
    gf_mul(&mut res, &a, &c_inv);

    let mut out = Zeroizing::new([0u8; 32]);
    pack25519(&mut out, &res);

    x.zeroize();
    a.zeroize();
    b.zeroize();
    c.zeroize();
    d.zeroize();
    e.zeroize();
    f.zeroize();
    c_inv.zeroize();
    res.zeroize();

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{agreement, rand::SystemRandom};

    fn from_hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn rfc7748_section_5_2_test_vectors() {
        // Vector 1
        let s1 = from_hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u1 = from_hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected1 =
            from_hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(*x25519_dh(&s1, &u1).unwrap(), expected1);

        // Vector 2
        let s2 = from_hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u2 = from_hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected2 =
            from_hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(*x25519_dh(&s2, &u2).unwrap(), expected2);

        // Iterated vector (1 and 1,000 iterations) from RFC 7748 §5.2
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        let out_1 = *scalarmult_raw(&k, &u);
        assert_eq!(
            hex::encode(out_1),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        );
        u = k;
        k = out_1;
        for _ in 1..1_000 {
            let next = *scalarmult_raw(&k, &u);
            u = k;
            k = next;
        }
        assert_eq!(
            hex::encode(k),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
    }

    #[test]
    fn rfc7748_section_6_1_dh_vector() {
        let alice_priv =
            from_hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub =
            from_hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_priv =
            from_hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub =
            from_hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = from_hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(x25519_public_from_private(&alice_priv), alice_pub);
        assert_eq!(x25519_public_from_private(&bob_priv), bob_pub);
        assert_eq!(*x25519_dh(&alice_priv, &bob_pub).unwrap(), shared);
        assert_eq!(*x25519_dh(&bob_priv, &alice_pub).unwrap(), shared);
    }

    #[test]
    fn differential_against_ring_x25519() {
        let rng = SystemRandom::new();
        for _ in 0..16 {
            let ring_ephem = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
            let ring_pub: [u8; 32] = ring_ephem.compute_public_key().unwrap().as_ref().try_into().unwrap();

            let mut our_priv = [0u8; 32];
            ring::rand::SecureRandom::fill(&rng, &mut our_priv).unwrap();
            let our_pub = x25519_public_from_private(&our_priv);

            let our_shared = x25519_dh(&our_priv, &ring_pub).unwrap();
            let ring_shared = agreement::agree_ephemeral(
                ring_ephem,
                &agreement::UnparsedPublicKey::new(&agreement::X25519, &our_pub),
                |s| <[u8; 32]>::try_from(s).unwrap(),
            )
            .unwrap();
            assert_eq!(*our_shared, ring_shared);
        }
    }

    #[test]
    fn rejects_all_low_order_points() {
        let priv_key =
            from_hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        for pt in &LOW_ORDER_X25519_POINTS {
            assert!(matches!(x25519_dh(&priv_key, pt), Err(CryptoError::SmallOrderKey)));
            // Also with MSB set
            let mut pt_msb = *pt;
            pt_msb[31] |= 0x80;
            assert!(matches!(
                x25519_dh(&priv_key, &pt_msb),
                Err(CryptoError::SmallOrderKey)
            ));
        }
    }
}
