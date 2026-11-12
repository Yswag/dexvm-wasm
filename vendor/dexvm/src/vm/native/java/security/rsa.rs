//! RSA public-key shims: `X509EncodedKeySpec` + `KeyFactory`. The actual
//! encryption lives in `javax_crypto`'s Cipher, which calls
//! [`rsa_pkcs1_encrypt`] when the transformation starts with `RSA`.

use crate::vm::native::*;
use num_bigint::BigUint;

fn byte_array(vm: &mut Vm, bytes: Vec<u8>) -> R {
    let data = bytes.into_iter().map(|b| b as i8).collect::<Vec<_>>();
    alloc_arr(vm, "B", data.len(), move || ArrayData::Byte(data))
}

fn trim_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

fn read_tlv<'a>(data: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pos + 2 > data.len() {
        return None;
    }
    let tag = data[*pos];
    let mut i = *pos + 1;
    let mut len = data[i] as usize;
    i += 1;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || i + n > data.len() {
            return None;
        }
        len = 0;
        for _ in 0..n {
            len = (len << 8) | data[i] as usize;
            i += 1;
        }
    }
    if i + len > data.len() {
        return None;
    }
    *pos = i + len;
    Some((tag, &data[i..i + len]))
}

/// Extracts (modulus, exponent) from a DER SubjectPublicKeyInfo.
fn parse_spki(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut p = 0;
    let (tag, spki) = read_tlv(der, &mut p)?;
    if tag != 0x30 {
        return None;
    }
    let mut q = 0;
    let (alg_tag, _alg) = read_tlv(spki, &mut q)?;
    if alg_tag != 0x30 {
        return None;
    }
    let (bits_tag, bits) = read_tlv(spki, &mut q)?;
    if bits_tag != 0x03 || bits.is_empty() {
        return None;
    }
    let inner = &bits[1..];
    let mut r = 0;
    let (rsa_tag, rsa) = read_tlv(inner, &mut r)?;
    if rsa_tag != 0x30 {
        return None;
    }
    let mut s = 0;
    let (n_tag, n) = read_tlv(rsa, &mut s)?;
    let (e_tag, e) = read_tlv(rsa, &mut s)?;
    if n_tag != 0x02 || e_tag != 0x02 {
        return None;
    }
    Some((trim_leading_zeros(n), trim_leading_zeros(e)))
}

fn rng_bytes(len: usize) -> Vec<u8> {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for byte in state.to_le_bytes() {
            if out.len() == len {
                break;
            }
            if byte != 0 {
                out.push(byte);
            }
        }
    }
    out
}

/// RSAES-PKCS1-v1_5 encryption: `0x00 0x02 PS 0x00 M`.
pub(crate) fn rsa_pkcs1_encrypt(
    modulus: &[u8],
    exponent: &[u8],
    msg: &[u8],
) -> Option<Vec<u8>> {
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    let k = ((n.bits() + 7) / 8) as usize;
    if k == 0 || msg.len() + 11 > k {
        return None;
    }
    let mut em = Vec::with_capacity(k);
    em.push(0);
    em.push(2);
    em.extend_from_slice(&rng_bytes(k - msg.len() - 3));
    em.push(0);
    em.extend_from_slice(msg);
    let m = BigUint::from_bytes_be(&em);
    let c = m.modpow(&e, &n);
    let mut out = c.to_bytes_be();
    if out.len() < k {
        let mut padded = vec![0u8; k - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    Some(out)
}

pub(crate) fn key_spec_init(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    let Some(object) = vm.arena.objects.get_mut(id as usize) else {
        return Err(npe(vm));
    };
    object.native = Some(Native::X509KeySpec(bytes));
    Ok(JValue::Null)
}

pub(crate) fn key_spec_get_encoded(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::X509KeySpec(bytes)) => {
            let bytes = bytes.clone();
            byte_array(vm, bytes)
        }
        _ => Err(npe(vm)),
    }
}

pub(crate) fn key_factory_get_instance(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(vm, "Ljava/security/KeyFactory;", Native::KeyFactory)
}

pub(crate) fn key_factory_generate_public(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = match payload(vm, args[1]) {
        Some(Native::X509KeySpec(bytes)) => bytes.clone(),
        _ => return Err(npe(vm)),
    };
    let (modulus, exponent) =
        parse_spki(&bytes).ok_or_else(|| NatErr::Throw(vm.err_iae("bad X509 public key")))?;
    alloc(
        vm,
        "Ljava/security/PublicKey;",
        Native::RsaPublicKey { modulus, exponent },
    )
}

pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/security/spec/X509EncodedKeySpec;",
        "<init>",
        "([B)V",
        true,
        key_spec_init
    ),
    ne!(
        "Ljava/security/spec/X509EncodedKeySpec;",
        "getEncoded",
        "()[B",
        true,
        key_spec_get_encoded
    ),
    ne!(
        "Ljava/security/spec/EncodedKeySpec;",
        "getEncoded",
        "()[B",
        true,
        key_spec_get_encoded
    ),
    ne!(
        "Ljava/security/KeyFactory;",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyFactory;",
        false,
        key_factory_get_instance
    ),
    ne!(
        "Ljava/security/KeyFactory;",
        "generatePublic",
        "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;",
        true,
        key_factory_generate_public
    ),
];
