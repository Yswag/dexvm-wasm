// wasm: java.security EC / P-256 (secp256r1) + javax.crypto.KeyAgreement (ECDH) host shims.

use crate::vm::native::*;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::Zero;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

// NIST P-256 / secp256r1 / prime256v1 domain parameters.
const P256_P_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P256_A_HEX: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const P256_B_HEX: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const P256_GX_HEX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const P256_GY_HEX: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const P256_N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn hex_biguint(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid hex constant")
}

fn hex_bigint(s: &str) -> BigInt {
    BigInt::from_biguint(Sign::Plus, hex_biguint(s))
}

pub(crate) fn is_p256_curve(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "secp256r1" | "prime256v1" | "p-256" | "p256" | "nistp256" | "1.2.840.10045.3.1.7"
    )
}

fn to_32_be(n: &BigUint) -> [u8; 32] {
    let raw = n.to_bytes_be();
    let mut out = [0u8; 32];
    if raw.len() >= 32 {
        out.copy_from_slice(&raw[raw.len() - 32..]);
    } else {
        out[32 - raw.len()..].copy_from_slice(&raw);
    }
    out
}

fn mod_add(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a + b) % p
}

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let a = a % p;
    let b = b % p;
    if a >= b {
        a - b
    } else {
        (a + p) - b
    }
}

fn mod_mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a * b) % p
}

fn mod_inv(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    let a = a % p;
    if a.is_zero() {
        return None;
    }
    let exp = p - BigUint::from(2u32);
    Some(a.modpow(&exp, p))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AffinePoint {
    Infinity,
    Point(BigUint, BigUint),
}

fn point_double(pt: &AffinePoint, a: &BigUint, p: &BigUint) -> AffinePoint {
    let AffinePoint::Point(x, y) = pt else {
        return AffinePoint::Infinity;
    };
    if y.is_zero() {
        return AffinePoint::Infinity;
    }
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    // lambda = (3*x^2 + a) / (2*y) mod p
    let x2 = mod_mul(x, x, p);
    let num = mod_add(&mod_mul(&three, &x2, p), a, p);
    let den = mod_mul(&two, y, p);
    let Some(den_inv) = mod_inv(&den, p) else {
        return AffinePoint::Infinity;
    };
    let lam = mod_mul(&num, &den_inv, p);
    let x3 = mod_sub(&mod_mul(&lam, &lam, p), &mod_mul(&two, x, p), p);
    let y3 = mod_sub(&mod_mul(&lam, &mod_sub(x, &x3, p), p), y, p);
    AffinePoint::Point(x3, y3)
}

fn point_add(p1: &AffinePoint, p2: &AffinePoint, a: &BigUint, p: &BigUint) -> AffinePoint {
    match (p1, p2) {
        (AffinePoint::Infinity, q) => q.clone(),
        (q, AffinePoint::Infinity) => q.clone(),
        (AffinePoint::Point(x1, y1), AffinePoint::Point(x2, y2)) => {
            if x1 == x2 {
                if y1 == y2 {
                    return point_double(p1, a, p);
                } else {
                    return AffinePoint::Infinity;
                }
            }
            let num = mod_sub(y2, y1, p);
            let den = mod_sub(x2, x1, p);
            let Some(den_inv) = mod_inv(&den, p) else {
                return AffinePoint::Infinity;
            };
            let lam = mod_mul(&num, &den_inv, p);
            let x3 = mod_sub(&mod_sub(&mod_mul(&lam, &lam, p), x1, p), x2, p);
            let y3 = mod_sub(&mod_mul(&lam, &mod_sub(x1, &x3, p), p), y1, p);
            AffinePoint::Point(x3, y3)
        }
    }
}

fn scalar_mul(k: &BigUint, base: &AffinePoint, a: &BigUint, p: &BigUint) -> AffinePoint {
    if k.is_zero() || matches!(base, AffinePoint::Infinity) {
        return AffinePoint::Infinity;
    }
    let mut acc = AffinePoint::Infinity;
    let mut cur = base.clone();
    let bits = k.bits();
    for i in 0..bits {
        if k.bit(i) {
            acc = point_add(&acc, &cur, a, p);
        }
        cur = point_double(&cur, a, p);
    }
    acc
}

fn is_on_p256(x: &BigUint, y: &BigUint, a: &BigUint, b: &BigUint, p: &BigUint) -> bool {
    if x >= p || y >= p {
        return false;
    }
    let lhs = mod_mul(y, y, p);
    let x2 = mod_mul(x, x, p);
    let x3 = mod_mul(&x2, x, p);
    let ax = mod_mul(a, x, p);
    let rhs = mod_add(&mod_add(&x3, &ax, p), b, p);
    lhs == rhs
}

/// Computes P-256 public key (x, y) from private scalar `s` (big-endian bytes).
pub(crate) fn p256_public_from_private(s_bytes: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let p = hex_biguint(P256_P_HEX);
    let a = hex_biguint(P256_A_HEX);
    let n = hex_biguint(P256_N_HEX);
    let g = AffinePoint::Point(hex_biguint(P256_GX_HEX), hex_biguint(P256_GY_HEX));
    let s = BigUint::from_bytes_be(s_bytes) % &n;
    if s.is_zero() {
        return None;
    }
    match scalar_mul(&s, &g, &a, &p) {
        AffinePoint::Point(x, y) => Some((to_32_be(&x), to_32_be(&y))),
        AffinePoint::Infinity => None,
    }
}

/// Computes P-256 ECDH shared secret (32-byte big-endian X coordinate of `s * Q`).
pub(crate) fn p256_ecdh(s_bytes: &[u8], pub_x: &[u8], pub_y: &[u8]) -> Option<[u8; 32]> {
    let p = hex_biguint(P256_P_HEX);
    let a = hex_biguint(P256_A_HEX);
    let b = hex_biguint(P256_B_HEX);
    let n = hex_biguint(P256_N_HEX);
    let x = BigUint::from_bytes_be(pub_x);
    let y = BigUint::from_bytes_be(pub_y);
    if !is_on_p256(&x, &y, &a, &b, &p) {
        return None;
    }
    let s = BigUint::from_bytes_be(s_bytes) % &n;
    if s.is_zero() {
        return None;
    }
    let q = AffinePoint::Point(x, y);
    match scalar_mul(&s, &q, &a, &p) {
        AffinePoint::Point(sx, _) => Some(to_32_be(&sx)),
        AffinePoint::Infinity => None,
    }
}

static KEYGEN_COUNTER: AtomicU64 = AtomicU64::new(1);

fn generate_p256_keypair() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let n = hex_biguint(P256_N_HEX);
    let n_minus_1 = &n - BigUint::from(1u32);
    loop {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        let ctr = KEYGEN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut h = Sha256::new();
        h.update(b"dexvm-p256-keygen-v1");
        h.update(nanos.to_le_bytes());
        h.update(ctr.to_le_bytes());
        let digest = h.finalize();
        let d = (BigUint::from_bytes_be(&digest) % &n_minus_1) + BigUint::from(1u32);
        let s_bytes = to_32_be(&d);
        if let Some((x, y)) = p256_public_from_private(&s_bytes) {
            return (s_bytes, x, y);
        }
    }
}

fn alloc_bigint(vm: &mut Vm, value: BigInt) -> R {
    alloc(vm, "Ljava/math/BigInteger;", Native::BigInt(value))
}

fn bigint_to_unsigned_be(vm: &Vm, v: JValue) -> Option<Vec<u8>> {
    match payload(vm, v) {
        Some(Native::BigInt(b)) => Some(b.to_bytes_be().1),
        _ => None,
    }
}

fn byte_array(vm: &mut Vm, bytes: Vec<u8>) -> R {
    let data = bytes.into_iter().map(|b| b as i8).collect::<Vec<_>>();
    alloc_arr(vm, "B", data.len(), move || ArrayData::Byte(data))
}

// ---- java.security.spec.ECGenParameterSpec ----

fn ec_gen_param_spec_init(vm: &mut Vm, args: &[JValue]) -> R {
    let name = jstr(vm, args[1])?;
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    vm.arena.objects[id as usize].native = Some(Native::EcGenParamSpec(name));
    Ok(JValue::Null)
}

fn ec_gen_param_spec_get_name(vm: &mut Vm, args: &[JValue]) -> R {
    let name = match payload(vm, args[0]) {
        Some(Native::EcGenParamSpec(s)) => s.clone(),
        _ => return Err(npe(vm)),
    };
    Ok(new_str(vm, &name))
}

// ---- java.security.AlgorithmParameters ----

fn alg_params_get_instance(vm: &mut Vm, args: &[JValue]) -> R {
    let algo = jstr(vm, args[0])?;
    alloc(
        vm,
        "Ljava/security/AlgorithmParameters;",
        Native::AlgorithmParams { algo, curve: None },
    )
}

fn alg_params_init_spec(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[1]) {
        Some(Native::EcGenParamSpec(name)) => name.clone(),
        Some(Native::EcParamSpec(name)) => name.clone(),
        _ => return Err(iae(vm, "unsupported AlgorithmParameterSpec")),
    };
    if !is_p256_curve(&curve) {
        return Err(iae(vm, format!("unsupported EC curve: {curve}")));
    }
    let Some(Native::AlgorithmParams { curve: dst, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *dst = Some("secp256r1".to_string());
    Ok(JValue::Null)
}

fn alg_params_get_param_spec(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::AlgorithmParams { curve: Some(c), .. }) => c.clone(),
        Some(Native::AlgorithmParams { curve: None, .. }) => {
            return Err(iae(vm, "AlgorithmParameters not initialized"));
        }
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/security/spec/ECParameterSpec;",
        Native::EcParamSpec(curve),
    )
}

// ---- java.security.spec.ECParameterSpec / EllipticCurve / ECFieldFp / ECPoint ----

fn ec_param_spec_get_curve(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::EcParamSpec(c)) => c.clone(),
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/security/spec/EllipticCurve;",
        Native::EcCurve(curve),
    )
}

fn ec_param_spec_get_generator(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcParamSpec(_)) => (),
        _ => return Err(npe(vm)),
    };
    let gx = to_32_be(&hex_biguint(P256_GX_HEX)).to_vec();
    let gy = to_32_be(&hex_biguint(P256_GY_HEX)).to_vec();
    alloc(
        vm,
        "Ljava/security/spec/ECPoint;",
        Native::EcPoint { x: gx, y: gy },
    )
}

fn ec_param_spec_get_order(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcParamSpec(_)) => (),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, hex_bigint(P256_N_HEX))
}

fn ec_param_spec_get_cofactor(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcParamSpec(_)) => (),
        _ => return Err(npe(vm)),
    };
    Ok(JValue::Int(1))
}

fn elliptic_curve_get_field(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::EcCurve(c)) => c.clone(),
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/security/spec/ECFieldFp;",
        Native::EcFieldFp(curve),
    )
}

fn elliptic_curve_get_a(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcCurve(_)) => (),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, hex_bigint(P256_A_HEX))
}

fn elliptic_curve_get_b(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcCurve(_)) => (),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, hex_bigint(P256_B_HEX))
}

fn ec_field_fp_get_p(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcFieldFp(_)) => (),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, hex_bigint(P256_P_HEX))
}

fn ec_field_fp_get_field_size(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = match payload(vm, args[0]) {
        Some(Native::EcFieldFp(_)) => (),
        _ => return Err(npe(vm)),
    };
    Ok(JValue::Int(256))
}

fn ec_point_init(vm: &mut Vm, args: &[JValue]) -> R {
    let x = bigint_to_unsigned_be(vm, args[1]).ok_or_else(|| npe(vm))?;
    let y = bigint_to_unsigned_be(vm, args[2]).ok_or_else(|| npe(vm))?;
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    vm.arena.objects[id as usize].native = Some(Native::EcPoint { x, y });
    Ok(JValue::Null)
}

fn ec_point_get_x(vm: &mut Vm, args: &[JValue]) -> R {
    let x = match payload(vm, args[0]) {
        Some(Native::EcPoint { x, .. }) => x.clone(),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, BigInt::from_bytes_be(Sign::Plus, &x))
}

fn ec_point_get_y(vm: &mut Vm, args: &[JValue]) -> R {
    let y = match payload(vm, args[0]) {
        Some(Native::EcPoint { y, .. }) => y.clone(),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, BigInt::from_bytes_be(Sign::Plus, &y))
}

// ---- ECPublicKeySpec / ECPrivateKeySpec ----

fn ec_pub_key_spec_init(vm: &mut Vm, args: &[JValue]) -> R {
    let (x, y) = match payload(vm, args[1]) {
        Some(Native::EcPoint { x, y }) => (x.clone(), y.clone()),
        _ => return Err(npe(vm)),
    };
    let curve = match payload(vm, args[2]) {
        Some(Native::EcParamSpec(c)) => c.clone(),
        _ => "secp256r1".to_string(),
    };
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    vm.arena.objects[id as usize].native = Some(Native::EcPublicKeySpec { x, y, curve });
    Ok(JValue::Null)
}

fn ec_pub_key_spec_get_w(vm: &mut Vm, args: &[JValue]) -> R {
    let (x, y) = match payload(vm, args[0]) {
        Some(Native::EcPublicKeySpec { x, y, .. }) => (x.clone(), y.clone()),
        _ => return Err(npe(vm)),
    };
    alloc(vm, "Ljava/security/spec/ECPoint;", Native::EcPoint { x, y })
}

fn ec_pub_key_spec_get_params(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::EcPublicKeySpec { curve, .. }) => curve.clone(),
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/security/spec/ECParameterSpec;",
        Native::EcParamSpec(curve),
    )
}

fn ec_priv_key_spec_init(vm: &mut Vm, args: &[JValue]) -> R {
    let s = bigint_to_unsigned_be(vm, args[1]).ok_or_else(|| npe(vm))?;
    let curve = match payload(vm, args[2]) {
        Some(Native::EcParamSpec(c)) => c.clone(),
        _ => "secp256r1".to_string(),
    };
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    vm.arena.objects[id as usize].native = Some(Native::EcPrivateKeySpec { s, curve });
    Ok(JValue::Null)
}

fn ec_priv_key_spec_get_s(vm: &mut Vm, args: &[JValue]) -> R {
    let s = match payload(vm, args[0]) {
        Some(Native::EcPrivateKeySpec { s, .. }) => s.clone(),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, BigInt::from_bytes_be(Sign::Plus, &s))
}

fn ec_priv_key_spec_get_params(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::EcPrivateKeySpec { curve, .. }) => curve.clone(),
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/security/spec/ECParameterSpec;",
        Native::EcParamSpec(curve),
    )
}

// ---- ECPublicKey / ECPrivateKey ----

fn ec_pub_key_get_w(vm: &mut Vm, args: &[JValue]) -> R {
    let (x, y) = match payload(vm, args[0]) {
        Some(Native::EcPublicKey { x, y, .. }) => (x.clone(), y.clone()),
        _ => return Err(npe(vm)),
    };
    alloc(vm, "Ljava/security/spec/ECPoint;", Native::EcPoint { x, y })
}

fn ec_pub_key_get_params(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::EcPublicKey { curve, .. }) | Some(Native::EcPrivateKey { curve, .. }) => {
            curve.clone()
        }
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/security/spec/ECParameterSpec;",
        Native::EcParamSpec(curve),
    )
}

fn ec_priv_key_get_s(vm: &mut Vm, args: &[JValue]) -> R {
    let s = match payload(vm, args[0]) {
        Some(Native::EcPrivateKey { s, .. }) => s.clone(),
        _ => return Err(npe(vm)),
    };
    alloc_bigint(vm, BigInt::from_bytes_be(Sign::Plus, &s))
}

fn ec_key_get_algorithm(vm: &mut Vm, args: &[JValue]) -> R {
    let algo = match payload(vm, args[0]) {
        Some(Native::EcPublicKey { .. }) | Some(Native::EcPrivateKey { .. }) => "EC",
        Some(Native::RsaPublicKey { .. }) => "RSA",
        Some(Native::Key(_)) => "AES",
        _ => return Err(npe(vm)),
    };
    Ok(new_str(vm, algo))
}

fn ec_key_get_format(vm: &mut Vm, args: &[JValue]) -> R {
    let fmt = match payload(vm, args[0]) {
        Some(Native::EcPublicKey { .. }) | Some(Native::RsaPublicKey { .. }) => "X.509",
        Some(Native::EcPrivateKey { .. }) => "PKCS#8",
        Some(Native::Key(_)) => "RAW",
        _ => return Err(npe(vm)),
    };
    Ok(new_str(vm, fmt))
}

fn ec_key_get_encoded(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::Key(bytes)) => {
            let bytes = bytes.clone();
            byte_array(vm, bytes)
        }
        Some(Native::EcPublicKey { x, y, .. }) => {
            // Uncompressed SEC1 point 0x04 || x(32) || y(32) wrapped in P-256 SPKI DER header.
            let mut x32 = [0u8; 32];
            let mut y32 = [0u8; 32];
            if x.len() >= 32 {
                x32.copy_from_slice(&x[x.len() - 32..]);
            } else {
                x32[32 - x.len()..].copy_from_slice(x);
            }
            if y.len() >= 32 {
                y32.copy_from_slice(&y[y.len() - 32..]);
            } else {
                y32[32 - y.len()..].copy_from_slice(y);
            }
            let spki_prefix: [u8; 26] = [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            let mut der = Vec::with_capacity(91);
            der.extend_from_slice(&spki_prefix);
            der.push(0x04);
            der.extend_from_slice(&x32);
            der.extend_from_slice(&y32);
            byte_array(vm, der)
        }
        _ => Err(iae(vm, "key encoding not supported")),
    }
}

// ---- java.security.KeyPair / KeyPairGenerator ----

fn key_pair_init(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    vm.arena.objects[id as usize].native = Some(Native::KeyPair {
        public: args[1],
        private: args[2],
    });
    Ok(JValue::Null)
}

fn key_pair_get_public(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::KeyPair { public, .. }) => Ok(*public),
        _ => Err(npe(vm)),
    }
}

fn key_pair_get_private(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::KeyPair { private, .. }) => Ok(*private),
        _ => Err(npe(vm)),
    }
}

fn kpg_get_instance(vm: &mut Vm, args: &[JValue]) -> R {
    let algo = jstr(vm, args[0])?;
    if !algo.eq_ignore_ascii_case("EC") {
        return Err(iae(
            vm,
            format!("unsupported KeyPairGenerator algorithm: {algo}"),
        ));
    }
    alloc(
        vm,
        "Ljava/security/KeyPairGenerator;",
        Native::KeyPairGenerator {
            algo: "EC".to_string(),
            curve: "secp256r1".to_string(),
        },
    )
}

fn kpg_init_spec(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[1]) {
        Some(Native::EcGenParamSpec(name)) | Some(Native::EcParamSpec(name)) => name.clone(),
        _ => return Err(iae(vm, "unsupported KeyPairGenerator AlgorithmParameterSpec")),
    };
    if !is_p256_curve(&curve) {
        return Err(iae(vm, format!("unsupported EC curve: {curve}")));
    }
    let Some(Native::KeyPairGenerator { curve: dst, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *dst = "secp256r1".to_string();
    Ok(JValue::Null)
}

fn kpg_init_keysize(vm: &mut Vm, args: &[JValue]) -> R {
    let bits = int_of(vm, args[1]);
    if bits != 256 {
        return Err(iae(vm, format!("unsupported EC key size: {bits}")));
    }
    let Some(Native::KeyPairGenerator { curve: dst, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *dst = "secp256r1".to_string();
    Ok(JValue::Null)
}

fn kpg_generate_key_pair(vm: &mut Vm, args: &[JValue]) -> R {
    let curve = match payload(vm, args[0]) {
        Some(Native::KeyPairGenerator { curve, .. }) => curve.clone(),
        _ => return Err(npe(vm)),
    };
    let (s, x, y) = generate_p256_keypair();
    let public = alloc(
        vm,
        "Ljava/security/interfaces/ECPublicKey;",
        Native::EcPublicKey {
            x: x.to_vec(),
            y: y.to_vec(),
            curve: curve.clone(),
        },
    )?;
    let private = alloc(
        vm,
        "Ljava/security/interfaces/ECPrivateKey;",
        Native::EcPrivateKey {
            s: s.to_vec(),
            curve,
        },
    )?;
    alloc(
        vm,
        "Ljava/security/KeyPair;",
        Native::KeyPair { public, private },
    )
}

// ---- javax.crypto.KeyAgreement (ECDH) ----

fn ka_get_instance(vm: &mut Vm, args: &[JValue]) -> R {
    let algo = jstr(vm, args[0])?;
    if !algo.eq_ignore_ascii_case("ECDH") {
        return Err(iae(vm, format!("unsupported KeyAgreement algorithm: {algo}")));
    }
    alloc(
        vm,
        "Ljavax/crypto/KeyAgreement;",
        Native::KeyAgreement {
            algo: "ECDH".to_string(),
            priv_key: None,
            shared: None,
        },
    )
}

fn ka_init(vm: &mut Vm, args: &[JValue]) -> R {
    let s = match payload(vm, args[1]) {
        Some(Native::EcPrivateKey { s, .. }) => s.clone(),
        _ => return Err(iae(vm, "KeyAgreement.init requires an ECPrivateKey")),
    };
    let Some(Native::KeyAgreement {
        priv_key, shared, ..
    }) = payload_mut(vm, args[0])
    else {
        return Err(npe(vm));
    };
    *priv_key = Some(s);
    *shared = None;
    Ok(JValue::Null)
}

fn ka_do_phase(vm: &mut Vm, args: &[JValue]) -> R {
    let (pub_x, pub_y) = match payload(vm, args[1]) {
        Some(Native::EcPublicKey { x, y, .. }) => (x.clone(), y.clone()),
        _ => return Err(iae(vm, "KeyAgreement.doPhase requires an ECPublicKey")),
    };
    let _last_phase = int_of(vm, args[2]) != 0;
    let priv_s = match payload(vm, args[0]) {
        Some(Native::KeyAgreement {
            priv_key: Some(s), ..
        }) => s.clone(),
        Some(Native::KeyAgreement { priv_key: None, .. }) => {
            return Err(iae(vm, "KeyAgreement not initialized"));
        }
        _ => return Err(npe(vm)),
    };
    let secret = p256_ecdh(&priv_s, &pub_x, &pub_y)
        .ok_or_else(|| iae(vm, "ECDH failed: invalid EC point or scalar"))?;
    if let Some(Native::KeyAgreement { shared, .. }) = payload_mut(vm, args[0]) {
        *shared = Some(secret.to_vec());
    }
    Ok(JValue::Null)
}

fn ka_generate_secret(vm: &mut Vm, args: &[JValue]) -> R {
    let secret = match payload(vm, args[0]) {
        Some(Native::KeyAgreement {
            shared: Some(s), ..
        }) => s.clone(),
        Some(Native::KeyAgreement { shared: None, .. }) => {
            return Err(iae(vm, "KeyAgreement.doPhase not called"));
        }
        _ => return Err(npe(vm)),
    };
    byte_array(vm, secret)
}

pub(crate) const TABLE: &[NativeEntry] = &[
    // ECGenParameterSpec
    ne!(
        "Ljava/security/spec/ECGenParameterSpec;",
        "<init>",
        "(Ljava/lang/String;)V",
        true,
        ec_gen_param_spec_init
    ),
    ne!(
        "Ljava/security/spec/ECGenParameterSpec;",
        "getName",
        "()Ljava/lang/String;",
        true,
        ec_gen_param_spec_get_name
    ),
    // AlgorithmParameters
    ne!(
        "Ljava/security/AlgorithmParameters;",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/AlgorithmParameters;",
        false,
        alg_params_get_instance
    ),
    ne!(
        "Ljava/security/AlgorithmParameters;",
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        true,
        alg_params_init_spec
    ),
    ne!(
        "Ljava/security/AlgorithmParameters;",
        "getParameterSpec",
        "(Ljava/lang/Class;)Ljava/security/spec/AlgorithmParameterSpec;",
        true,
        alg_params_get_param_spec
    ),
    // ECParameterSpec
    ne!(
        "Ljava/security/spec/ECParameterSpec;",
        "getCurve",
        "()Ljava/security/spec/EllipticCurve;",
        true,
        ec_param_spec_get_curve
    ),
    ne!(
        "Ljava/security/spec/ECParameterSpec;",
        "getGenerator",
        "()Ljava/security/spec/ECPoint;",
        true,
        ec_param_spec_get_generator
    ),
    ne!(
        "Ljava/security/spec/ECParameterSpec;",
        "getOrder",
        "()Ljava/math/BigInteger;",
        true,
        ec_param_spec_get_order
    ),
    ne!(
        "Ljava/security/spec/ECParameterSpec;",
        "getCofactor",
        "()I",
        true,
        ec_param_spec_get_cofactor
    ),
    // EllipticCurve
    ne!(
        "Ljava/security/spec/EllipticCurve;",
        "getField",
        "()Ljava/security/spec/ECField;",
        true,
        elliptic_curve_get_field
    ),
    ne!(
        "Ljava/security/spec/EllipticCurve;",
        "getA",
        "()Ljava/math/BigInteger;",
        true,
        elliptic_curve_get_a
    ),
    ne!(
        "Ljava/security/spec/EllipticCurve;",
        "getB",
        "()Ljava/math/BigInteger;",
        true,
        elliptic_curve_get_b
    ),
    // ECFieldFp
    ne!(
        "Ljava/security/spec/ECFieldFp;",
        "getP",
        "()Ljava/math/BigInteger;",
        true,
        ec_field_fp_get_p
    ),
    ne!(
        "Ljava/security/spec/ECFieldFp;",
        "getFieldSize",
        "()I",
        true,
        ec_field_fp_get_field_size
    ),
    // ECPoint
    ne!(
        "Ljava/security/spec/ECPoint;",
        "<init>",
        "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V",
        true,
        ec_point_init
    ),
    ne!(
        "Ljava/security/spec/ECPoint;",
        "getAffineX",
        "()Ljava/math/BigInteger;",
        true,
        ec_point_get_x
    ),
    ne!(
        "Ljava/security/spec/ECPoint;",
        "getAffineY",
        "()Ljava/math/BigInteger;",
        true,
        ec_point_get_y
    ),
    // ECPublicKeySpec / ECPrivateKeySpec
    ne!(
        "Ljava/security/spec/ECPublicKeySpec;",
        "<init>",
        "(Ljava/security/spec/ECPoint;Ljava/security/spec/ECParameterSpec;)V",
        true,
        ec_pub_key_spec_init
    ),
    ne!(
        "Ljava/security/spec/ECPublicKeySpec;",
        "getW",
        "()Ljava/security/spec/ECPoint;",
        true,
        ec_pub_key_spec_get_w
    ),
    ne!(
        "Ljava/security/spec/ECPublicKeySpec;",
        "getParams",
        "()Ljava/security/spec/ECParameterSpec;",
        true,
        ec_pub_key_spec_get_params
    ),
    ne!(
        "Ljava/security/spec/ECPrivateKeySpec;",
        "<init>",
        "(Ljava/math/BigInteger;Ljava/security/spec/ECParameterSpec;)V",
        true,
        ec_priv_key_spec_init
    ),
    ne!(
        "Ljava/security/spec/ECPrivateKeySpec;",
        "getS",
        "()Ljava/math/BigInteger;",
        true,
        ec_priv_key_spec_get_s
    ),
    ne!(
        "Ljava/security/spec/ECPrivateKeySpec;",
        "getParams",
        "()Ljava/security/spec/ECParameterSpec;",
        true,
        ec_priv_key_spec_get_params
    ),
    // ECPublicKey / ECPrivateKey / Key
    ne!(
        "Ljava/security/interfaces/ECPublicKey;",
        "getW",
        "()Ljava/security/spec/ECPoint;",
        true,
        ec_pub_key_get_w
    ),
    ne!(
        "Ljava/security/interfaces/ECPublicKey;",
        "getParams",
        "()Ljava/security/spec/ECParameterSpec;",
        true,
        ec_pub_key_get_params
    ),
    ne!(
        "Ljava/security/interfaces/ECPublicKey;",
        "getAlgorithm",
        "()Ljava/lang/String;",
        true,
        ec_key_get_algorithm
    ),
    ne!(
        "Ljava/security/interfaces/ECPublicKey;",
        "getFormat",
        "()Ljava/lang/String;",
        true,
        ec_key_get_format
    ),
    ne!(
        "Ljava/security/interfaces/ECPublicKey;",
        "getEncoded",
        "()[B",
        true,
        ec_key_get_encoded
    ),
    ne!(
        "Ljava/security/interfaces/ECPrivateKey;",
        "getS",
        "()Ljava/math/BigInteger;",
        true,
        ec_priv_key_get_s
    ),
    ne!(
        "Ljava/security/interfaces/ECPrivateKey;",
        "getParams",
        "()Ljava/security/spec/ECParameterSpec;",
        true,
        ec_pub_key_get_params
    ),
    ne!(
        "Ljava/security/interfaces/ECPrivateKey;",
        "getAlgorithm",
        "()Ljava/lang/String;",
        true,
        ec_key_get_algorithm
    ),
    ne!(
        "Ljava/security/interfaces/ECPrivateKey;",
        "getFormat",
        "()Ljava/lang/String;",
        true,
        ec_key_get_format
    ),
    ne!(
        "Ljava/security/interfaces/ECKey;",
        "getParams",
        "()Ljava/security/spec/ECParameterSpec;",
        true,
        ec_pub_key_get_params
    ),
    ne!(
        "Ljava/security/PublicKey;",
        "getEncoded",
        "()[B",
        true,
        ec_key_get_encoded
    ),
    ne!(
        "Ljava/security/Key;",
        "getEncoded",
        "()[B",
        true,
        ec_key_get_encoded
    ),
    ne!(
        "Ljava/security/Key;",
        "getAlgorithm",
        "()Ljava/lang/String;",
        true,
        ec_key_get_algorithm
    ),
    ne!(
        "Ljava/security/Key;",
        "getFormat",
        "()Ljava/lang/String;",
        true,
        ec_key_get_format
    ),
    // KeyPair
    ne!(
        "Ljava/security/KeyPair;",
        "<init>",
        "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V",
        true,
        key_pair_init
    ),
    ne!(
        "Ljava/security/KeyPair;",
        "getPublic",
        "()Ljava/security/PublicKey;",
        true,
        key_pair_get_public
    ),
    ne!(
        "Ljava/security/KeyPair;",
        "getPrivate",
        "()Ljava/security/PrivateKey;",
        true,
        key_pair_get_private
    ),
    // KeyPairGenerator
    ne!(
        "Ljava/security/KeyPairGenerator;",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
        false,
        kpg_get_instance
    ),
    ne!(
        "Ljava/security/KeyPairGenerator;",
        "initialize",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        true,
        kpg_init_spec
    ),
    ne!(
        "Ljava/security/KeyPairGenerator;",
        "initialize",
        "(Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)V",
        true,
        kpg_init_spec
    ),
    ne!(
        "Ljava/security/KeyPairGenerator;",
        "initialize",
        "(I)V",
        true,
        kpg_init_keysize
    ),
    ne!(
        "Ljava/security/KeyPairGenerator;",
        "generateKeyPair",
        "()Ljava/security/KeyPair;",
        true,
        kpg_generate_key_pair
    ),
    // javax.crypto.KeyAgreement
    ne!(
        "Ljavax/crypto/KeyAgreement;",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/KeyAgreement;",
        false,
        ka_get_instance
    ),
    ne!(
        "Ljavax/crypto/KeyAgreement;",
        "init",
        "(Ljava/security/Key;)V",
        true,
        ka_init
    ),
    ne!(
        "Ljavax/crypto/KeyAgreement;",
        "init",
        "(Ljava/security/Key;Ljava/security/SecureRandom;)V",
        true,
        ka_init
    ),
    ne!(
        "Ljavax/crypto/KeyAgreement;",
        "doPhase",
        "(Ljava/security/Key;Z)Ljava/security/Key;",
        true,
        ka_do_phase
    ),
    ne!(
        "Ljavax/crypto/KeyAgreement;",
        "generateSecret",
        "()[B",
        true,
        ka_generate_secret
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5903 Section 8.1 — 256-bit Random ECP Group (Group 19 / P-256).
    #[test]
    fn rfc5903_p256_ecdh_vector() {
        let di = hex_bytes("C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433");
        let gxi = hex_bytes("DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180");
        let gyi = hex_bytes("5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3");

        let dr = hex_bytes("C6EF9C5D 78AE012A 011164AC B397CE20 88685D8F 06BF9BE0 B283AB46 476BEE53");
        let gxr = hex_bytes("D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63");
        let gyr = hex_bytes("56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB");

        let expected_z =
            hex_bytes("D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE");

        let (pxi, pyi) = p256_public_from_private(&di).unwrap();
        assert_eq!(pxi.as_slice(), gxi.as_slice());
        assert_eq!(pyi.as_slice(), gyi.as_slice());

        let (pxr, pyr) = p256_public_from_private(&dr).unwrap();
        assert_eq!(pxr.as_slice(), gxr.as_slice());
        assert_eq!(pyr.as_slice(), gyr.as_slice());

        let z1 = p256_ecdh(&di, &gxr, &gyr).unwrap();
        let z2 = p256_ecdh(&dr, &gxi, &gyi).unwrap();
        assert_eq!(z1.as_slice(), expected_z.as_slice());
        assert_eq!(z2.as_slice(), expected_z.as_slice());
    }
}
