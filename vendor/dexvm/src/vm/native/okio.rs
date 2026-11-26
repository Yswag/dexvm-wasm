//! okio host shims: in-memory `BufferedSource`/`Buffer` over a byte cursor.

use super::*;
use crate::permission::{FilesystemPermission, Permission};
use crate::vm::native::okhttp::resp_body_bytes;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};
use std::io::Write as _;

// ---- okio.ByteString: an immutable byte sequence, backed by a plain byte array ----

fn byte_string_alloc(vm: &mut Vm, bytes: Vec<u8>) -> R {
    let data: Vec<i8> = bytes.iter().map(|&b| b as i8).collect();
    alloc(
        vm,
        "Lokio/ByteString;",
        Native::Array(ArrayData::Byte(data)),
    )
}

fn byte_string_digest(
    vm: &mut Vm,
    args: &[JValue],
    digest: fn(&[u8]) -> Vec<u8>,
) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    byte_string_alloc(vm, digest(&bytes))
}

fn byte_string_md5(vm: &mut Vm, args: &[JValue]) -> R {
    byte_string_digest(vm, args, |bytes| md5::Md5::digest(bytes).to_vec())
}

fn byte_string_sha1(vm: &mut Vm, args: &[JValue]) -> R {
    byte_string_digest(vm, args, |bytes| sha1::Sha1::digest(bytes).to_vec())
}

fn byte_string_decode_base64(vm: &mut Vm, args: &[JValue]) -> R {
    // Companion method: args[0] is the receiver, args[1] the string.
    let s = jstr(vm, args[1])?;
    match BASE64_STD.decode(s.trim()) {
        Ok(bytes) => byte_string_alloc(vm, bytes),
        Err(_) => Ok(JValue::Null),
    }
}

fn byte_string_encode_utf8(vm: &mut Vm, args: &[JValue]) -> R {
    // Companion method: args[0] is the receiver, args[1] the string.
    let s = jstr(vm, args[1])?;
    byte_string_alloc(vm, s.into_bytes())
}

fn byte_string_bytes(vm: &Vm, args: &[JValue]) -> Option<Vec<u8>> {
    match payload(vm, args[0]) {
        Some(Native::Array(ArrayData::Byte(bs))) => Some(bs.iter().map(|&b| b as u8).collect()),
        _ => None,
    }
}

fn byte_string_hex(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(new_str(vm, &hex))
}

fn byte_string_to_byte_array(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    let data: Vec<i8> = bytes.iter().map(|&b| b as i8).collect();
    alloc_arr(vm, "B", data.len(), move || ArrayData::Byte(data))
}

fn byte_string_sha256(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    byte_string_alloc(vm, Sha256::digest(&bytes).to_vec())
}

fn byte_string_sha512(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    byte_string_alloc(vm, Sha512::digest(&bytes).to_vec())
}

fn byte_string_get_byte(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    let i = int_of(vm, args[1]);
    match bytes.get(i as usize) {
        Some(&b) => Ok(JValue::Int(b as i8 as i32)),
        None => Err(iae(vm, format!("index {i} out of bounds"))),
    }
}

fn byte_string_size(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    Ok(JValue::Int(bytes.len() as i32))
}

fn byte_string_utf8(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = byte_string_bytes(vm, args).ok_or_else(|| npe(vm))?;
    let s = String::from_utf8_lossy(&bytes).into_owned();
    Ok(new_str(vm, &s))
}

pub(crate) fn okio_source_input_stream(vm: &mut Vm, args: &[JValue]) -> R {
    let (bytes, pos) = match payload(vm, args[0]) {
        Some(Native::ByteArrayInputStream { bytes, pos }) => (bytes.clone(), *pos),
        Some(Native::Str(s)) => (s.as_bytes().to_vec(), 0),
        _ => return Err(npe(vm)),
    };
    alloc(vm, "Lokio/BufferedSource;", Native::OkioBuf { bytes, pos })
}

/// `Okio.source(File)` — reads the file's real bytes; throws
/// `java.io.FileNotFoundException` when the file does not exist, exactly
/// like okio. Callers rely on the exception to fall back to the network.
pub(crate) fn okio_source_file(vm: &mut Vm, args: &[JValue]) -> R {
    let path = match payload(vm, args[0]) {
        Some(Native::File { path }) => path.clone(),
        _ => return Err(npe(vm)),
    };
    check_native_permission(
        vm,
        &Permission::Filesystem(FilesystemPermission::ReadPath(path.clone())),
    )?;
    let bytes =
        std::fs::read(&path).map_err(|_| fnf(vm, format!("{path} (No such file or directory)")))?;
    alloc(
        vm,
        "Lokio/BufferedSource;",
        Native::OkioBuf { bytes, pos: 0 },
    )
}

pub(crate) fn okio_source_response_body(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = resp_body_bytes(vm, args[0])?;
    alloc(
        vm,
        "Lokio/BufferedSource;",
        Native::OkioBuf { bytes, pos: 0 },
    )
}

/// Reads the unread bytes of any of our eager, in-memory `Source`-shaped
/// payloads (this VM has no real streaming — every source is fully
/// buffered up front).
fn okio_bytes_of(vm: &Vm, v: JValue) -> Option<Vec<u8>> {
    match payload(vm, v) {
        Some(Native::OkioBuf { bytes, pos }) => Some(bytes[*pos..].to_vec()),
        Some(Native::ByteArrayInputStream { bytes, pos }) => Some(bytes[*pos..].to_vec()),
        Some(Native::Str(s)) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// `InflaterSource(source, inflater)`: eagerly reads and decompresses the
/// wrapped source, then behaves exactly like any other in-memory
/// `BufferedSource` from then on.
pub(crate) fn okio_inflater_source_init(vm: &mut Vm, args: &[JValue]) -> R {
    let compressed = okio_bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    let nowrap = matches!(
        payload(vm, args[2]),
        Some(Native::Inflater { nowrap: true, .. })
    );
    let decompressed = if nowrap {
        miniz_oxide::inflate::decompress_to_vec(&compressed)
    } else {
        miniz_oxide::inflate::decompress_to_vec_zlib(&compressed)
    }
    .map_err(|_| ioe(vm, "invalid deflate data"))?;
    let Some(JValue::Obj(this)) = args.first().copied() else {
        return Err(npe(vm));
    };
    vm.arena.objects[this as usize].native = Some(Native::OkioBuf {
        bytes: decompressed,
        pos: 0,
    });
    Ok(JValue::Null)
}

/// `Okio.cipherSource(source, cipher)`: eagerly reads the wrapped source and
/// runs it through the already-initialized `Cipher` (decrypt or encrypt,
/// whichever mode the caller set up), yielding another in-memory source.
pub(crate) fn okio_cipher_source(vm: &mut Vm, args: &[JValue]) -> R {
    let input = okio_bytes_of(vm, args[0]).ok_or_else(|| npe(vm))?;
    let len = input.len() as i32;
    let data: Vec<i8> = input.iter().map(|&b| b as i8).collect();
    let arr = alloc_arr(vm, "B", data.len(), move || ArrayData::Byte(data))?;
    let out = crate::vm::native::java::javax_crypto::cipher_do_final(
        vm,
        &[args[1], arr, JValue::Int(0), JValue::Int(len)],
    )?;
    let bytes = bytes_of(vm, out).unwrap_or_default();
    alloc(vm, "Lokio/CipherSource;", Native::OkioBuf { bytes, pos: 0 })
}

/// `ForwardingSource(delegate)`: this VM has no partial reads to forward
/// through, so it's equivalent to just aliasing the delegate's buffer.
pub(crate) fn okio_forwarding_source_init(vm: &mut Vm, args: &[JValue]) -> R {
    let bytes = okio_bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    let Some(JValue::Obj(this)) = args.first().copied() else {
        return Err(npe(vm));
    };
    vm.arena.objects[this as usize].native = Some(Native::OkioBuf { bytes, pos: 0 });
    Ok(JValue::Null)
}

/// `ForwardingSource.read(sink, byteCount)`: drains up to `byteCount` bytes
/// into `sink`'s buffer (both share the same in-memory `OkioBuf` shape).
pub(crate) fn okio_forwarding_source_read(vm: &mut Vm, args: &[JValue]) -> R {
    let want = long_of(vm, args[2]).max(0) as usize;
    let chunk = match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, pos }) => {
            let n = (bytes.len() - *pos).min(want);
            let chunk = bytes[*pos..*pos + n].to_vec();
            *pos += n;
            chunk
        }
        _ => return Err(npe(vm)),
    };
    if chunk.is_empty() {
        return Ok(JValue::Long(-1));
    }
    let n = chunk.len() as i64;
    match payload_mut(vm, args[1]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(&chunk),
        _ => return Err(npe(vm)),
    }
    Ok(JValue::Long(n))
}

fn file_arg_path(vm: &mut Vm, arg: JValue) -> Result<String, NatErr> {
    match payload(vm, arg) {
        Some(Native::File { path }) => Ok(path.clone()),
        _ => Err(npe(vm)),
    }
}

pub(crate) fn okio_sink_file(vm: &mut Vm, args: &[JValue]) -> R {
    let path = file_arg_path(vm, args[0])?;
    check_native_permission(
        vm,
        &Permission::Filesystem(FilesystemPermission::WritePath(path.clone())),
    )?;
    let append = args.get(1).is_some_and(|v| int_of(vm, *v) != 0);
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(!append)
        .append(append)
        .open(&path)
        .map_err(|e| fnf(vm, e.to_string()))?;
    alloc(
        vm,
        "Lokio/BufferedSink;",
        Native::OkioSink {
            path,
            bytes: Vec::new(),
            flushed: 0,
            closed: false,
        },
    )
}

/// `source()` is already a BufferedSource for our in-memory payloads.
pub(crate) fn okio_identity(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = vm;
    Ok(args[0])
}

// wasm: Okio.buffer(Source) drains custom DEX Source/ForwardingSource subclasses
// via their bytecode read(Buffer, Long) so streaming decryptors (e.g. MANGA Plus XOR) run.
pub(crate) fn okio_buffer_source(vm: &mut Vm, args: &[JValue]) -> R {
    let src = args[0];
    let JValue::Obj(obj_id) = src else {
        return Ok(src);
    };
    let read_ref = MethodRef {
        name: vm.intern("read"),
        sig: vm.intern("(Lokio/Buffer;J)J"),
        ret: 0,
        args: Vec::new(),
        class_desc: 0,
    };
    let target = match vm.resolve_target(InvokeKind::Virtual, &read_ref, Some(obj_id), 0) {
        Ok(t @ Target::Bytecode { .. }) => t,
        _ => return Ok(src),
    };
    let sink = alloc(
        vm,
        "Lokio/Buffer;",
        Native::OkioBuf {
            bytes: Vec::new(),
            pos: 0,
        },
    )?;
    loop {
        let raw_n = vm
            .call_target(target.clone(), vec![src, sink, JValue::Long(65536)])
            .map_err(nat_fatal)?;
        let n = long_of(vm, raw_n);
        if n <= 0 {
            break;
        }
    }
    Ok(sink)
}

fn flush_sink(vm: &mut Vm, sink: JValue) -> Result<(), NatErr> {
    let Some(Native::OkioSink {
        path,
        bytes,
        flushed,
        closed,
    }) = payload(vm, sink)
    else {
        return Ok(());
    };
    let (path, pending, start, closed) = (path.clone(), bytes.clone(), *flushed, *closed);
    if closed || start >= pending.len() {
        return Ok(());
    }
    check_native_permission(
        vm,
        &Permission::Filesystem(FilesystemPermission::WritePath(path.clone())),
    )?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| fnf(vm, e.to_string()))?;
    file.write_all(&pending[start..])
        .map_err(|e| ioe(vm, e.to_string()))?;
    if let Some(Native::OkioSink { flushed, .. }) = payload_mut(vm, sink) {
        *flushed = pending.len();
    }
    Ok(())
}

pub(crate) fn okio_flush(vm: &mut Vm, args: &[JValue]) -> R {
    flush_sink(vm, args[0])?;
    Ok(JValue::Null)
}

pub(crate) fn okio_close(vm: &mut Vm, args: &[JValue]) -> R {
    flush_sink(vm, args[0])?;
    if let Some(Native::OkioSink { closed, .. }) = payload_mut(vm, args[0]) {
        *closed = true;
    }
    Ok(JValue::Null)
}

pub(crate) fn okio_sink_write_bytes(vm: &mut Vm, args: &[JValue]) -> R {
    let data = bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    let (offset, length) = if args.len() >= 4 {
        let offset = usize::try_from(int_of(vm, args[2])).unwrap_or(usize::MAX);
        let length = usize::try_from(int_of(vm, args[3])).unwrap_or(usize::MAX);
        (offset, length)
    } else {
        (0, data.len())
    };
    let Some(end) = offset.checked_add(length).filter(|end| *end <= data.len()) else {
        return Err(iae(vm, "byte range out of bounds"));
    };
    let Some(Native::OkioSink { bytes, closed, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    if *closed {
        return Err(ioe(vm, "closed"));
    }
    bytes.extend_from_slice(&data[offset..end]);
    Ok(args[0])
}

pub(crate) fn okio_sink_write_utf8(vm: &mut Vm, args: &[JValue]) -> R {
    let value = jstr(vm, args[1])?;
    let Some(Native::OkioSink { bytes, closed, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    if *closed {
        return Err(ioe(vm, "closed"));
    }
    bytes.extend_from_slice(value.as_bytes());
    Ok(args[0])
}

pub(crate) fn okio_get_buffer(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::OkioBuf { bytes, pos }) = payload(vm, args[0]) else {
        return Err(npe(vm));
    };
    let (bytes, pos) = (bytes.clone(), *pos);
    alloc(vm, "Lokio/Buffer;", Native::OkioBuf { bytes, pos })
}

pub(crate) fn okio_request(vm: &mut Vm, args: &[JValue]) -> R {
    let want = int_of(vm, args[1]).max(0) as usize;
    let Some(Native::OkioBuf { bytes, pos }) = payload(vm, args[0]) else {
        return Err(npe(vm));
    };
    Ok(JValue::Int(i32::from(pos + want <= bytes.len())))
}

pub(crate) fn okio_read_byte_array(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    let data = bytes[*pos..].iter().map(|&b| b as i8).collect::<Vec<_>>();
    *pos = bytes.len();
    let len = data.len();
    alloc_arr(vm, "B", len, move || ArrayData::Byte(data))
}

pub(crate) fn okio_read_byte_array_count(vm: &mut Vm, args: &[JValue]) -> R {
    let n = long_of(vm, args[1]).max(0) as usize;
    let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    let end = (*pos + n).min(bytes.len());
    let data = bytes[*pos..end].iter().map(|&b| b as i8).collect::<Vec<_>>();
    *pos = end;
    let len = data.len();
    alloc_arr(vm, "B", len, move || ArrayData::Byte(data))
}

pub(crate) fn okio_read_utf8(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    let s = String::from_utf8_lossy(&bytes[*pos..]).into_owned();
    *pos = bytes.len();
    Ok(new_str(vm, &s))
}

pub(crate) fn okio_exhausted(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::OkioBuf { bytes, pos }) = payload(vm, args[0]) else {
        return Err(npe(vm));
    };
    Ok(JValue::Int(i32::from(*pos >= bytes.len())))
}

/// okio.Buffer.get(long): indexed byte access, relative to the unread cursor.
pub(crate) fn okio_buffer_get(vm: &mut Vm, args: &[JValue]) -> R {
    let i = match args[1] {
        JValue::Long(n) => n,
        JValue::Int(n) => n as i64,
        _ => return Err(iae(vm, "invalid index")),
    };
    let Some(Native::OkioBuf { bytes, pos }) = payload(vm, args[0]) else {
        return Err(npe(vm));
    };
    let idx = *pos as i64 + i;
    match bytes.get(idx as usize) {
        Some(&b) => Ok(JValue::Int(b as i8 as i32)),
        None => Err(iae(vm, format!("index {i} out of bounds"))),
    }
}

// wasm: okio.Buffer.copyTo(out, offset, byteCount) — non-consuming slice copy.
fn okio_buffer_copy_to_impl(
    vm: &mut Vm,
    src: JValue,
    dst: JValue,
    offset: i64,
    byte_count: i64,
) -> R {
    if offset < 0 || byte_count < 0 {
        return Err(iae(vm, "copyTo: negative offset or byteCount"));
    }
    let off = offset as usize;
    let cnt = byte_count as usize;
    let Some(end) = off.checked_add(cnt) else {
        return Err(iae(vm, "copyTo: overflow"));
    };
    let slice = {
        let Some(Native::OkioBuf { bytes, pos }) = payload(vm, src) else {
            return Err(npe(vm));
        };
        let avail = bytes.len().saturating_sub(*pos);
        if end > avail {
            return Err(iae(vm, "copyTo: range out of bounds"));
        }
        bytes[*pos + off..*pos + end].to_vec()
    };
    let Some(Native::OkioBuf { bytes, .. }) = payload_mut(vm, dst) else {
        return Err(npe(vm));
    };
    bytes.extend_from_slice(&slice);
    Ok(src)
}

pub(crate) fn okio_buffer_copy_to(vm: &mut Vm, args: &[JValue]) -> R {
    let offset = long_of(vm, args[2]);
    let byte_count = long_of(vm, args[3]);
    okio_buffer_copy_to_impl(vm, args[0], args[1], offset, byte_count)
}

pub(crate) fn okio_buffer_copy_to_all(vm: &mut Vm, args: &[JValue]) -> R {
    let avail = match payload(vm, args[0]) {
        Some(Native::OkioBuf { bytes, pos }) => bytes.len().saturating_sub(*pos) as i64,
        _ => return Err(npe(vm)),
    };
    okio_buffer_copy_to_impl(vm, args[0], args[1], 0, avail)
}

pub(crate) fn okio_buffer_copy_to_default(vm: &mut Vm, args: &[JValue]) -> R {
    let mask = int_of(vm, args[4]);
    let avail = match payload(vm, args[0]) {
        Some(Native::OkioBuf { bytes, pos }) => bytes.len().saturating_sub(*pos) as i64,
        _ => return Err(npe(vm)),
    };
    let offset = if (mask & 2) != 0 { 0 } else { long_of(vm, args[2]) };
    let byte_count = if (mask & 4) != 0 {
        avail.saturating_sub(offset)
    } else {
        long_of(vm, args[3])
    };
    okio_buffer_copy_to_impl(vm, args[0], args[1], offset, byte_count)
}

// wasm: okio.BufferedSource.readAll(Sink) / Buffer.readAll(Sink) -> long.
pub(crate) fn okio_read_all(vm: &mut Vm, args: &[JValue]) -> R {
    let data = {
        let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, args[0]) else {
            return Err(npe(vm));
        };
        let slice = bytes[*pos..].to_vec();
        *pos = bytes.len();
        slice
    };
    let count = data.len() as i64;
    match payload_mut(vm, args[1]) {
        Some(Native::OkioBuf { bytes, .. }) => {
            bytes.extend_from_slice(&data);
            Ok(JValue::Long(count))
        }
        Some(Native::OkioSink { bytes, closed, .. }) => {
            if *closed {
                return Err(ioe(vm, "closed"));
            }
            bytes.extend_from_slice(&data);
            Ok(JValue::Long(count))
        }
        _ => Err(npe(vm)),
    }
}

pub(crate) fn lazy_byte_string_companion(vm: &mut Vm) -> JValue {
    alloc(vm, "Lokio/ByteString$Companion;", Native::Opaque).unwrap_or(JValue::Null)
}

/// `okio.Buffer()` — the no-arg constructor leaves the object without a
/// payload, so writeTo/read paths would NPE; install an empty buffer.
fn okio_buffer_init(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    let Some(object) = vm.arena.objects.get_mut(id as usize) else {
        return Err(npe(vm));
    };
    object.native = Some(Native::OkioBuf {
        bytes: Vec::new(),
        pos: 0,
    });
    Ok(JValue::Null)
}

fn okio_buffer_size(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::OkioBuf { bytes, pos }) => Ok(JValue::Long((bytes.len() - pos) as i64)),
        _ => Err(npe(vm)),
    }
}

fn okio_buffer_write(vm: &mut Vm, args: &[JValue]) -> R {
    let input = bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(&input),
        _ => return Err(npe(vm)),
    }
    Ok(args[0])
}

fn okio_buffer_write_range(vm: &mut Vm, args: &[JValue]) -> R {
    let input = bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    let off = int_of(vm, args[2]).max(0) as usize;
    let len = int_of(vm, args[3]).max(0) as usize;
    let end = off.saturating_add(len).min(input.len());
    let slice = if off <= end { &input[off..end] } else { &[] };
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(slice),
        _ => return Err(npe(vm)),
    }
    Ok(args[0])
}

fn okio_buffer_write_utf8(vm: &mut Vm, args: &[JValue]) -> R {
    let s = jstr(vm, args[1])?;
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(s.as_bytes()),
        _ => return Err(npe(vm)),
    }
    Ok(args[0])
}

fn okio_buffer_write_int_le(vm: &mut Vm, args: &[JValue]) -> R {
    let v = int_of(vm, args[1]);
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(&v.to_le_bytes()),
        _ => return Err(npe(vm)),
    }
    Ok(args[0])
}

fn okio_buffer_input_stream(vm: &mut Vm, args: &[JValue]) -> R {
    let (bytes, pos) = match payload(vm, args[0]) {
        Some(Native::OkioBuf { bytes, pos }) => (bytes.clone(), *pos),
        _ => return Err(npe(vm)),
    };
    alloc(
        vm,
        "Ljava/io/InputStream;",
        Native::ByteArrayInputStream { bytes, pos },
    )
}

fn okio_buffer_write_all(vm: &mut Vm, args: &[JValue]) -> R {
    let source = okio_bytes_of(vm, args[1]).ok_or_else(|| npe(vm))?;
    let n = source.len() as i64;
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(&source),
        _ => return Err(npe(vm)),
    }
    Ok(JValue::Long(n))
}

fn okio_buffer_read_into(vm: &mut Vm, args: &[JValue]) -> R {
    let want = long_of(vm, args[2]).max(0) as usize;
    let chunk = match payload_mut(vm, args[1]) {
        Some(Native::OkioBuf { bytes, pos }) => {
            let n = (bytes.len() - *pos).min(want);
            let chunk = bytes[*pos..*pos + n].to_vec();
            *pos += n;
            chunk
        }
        _ => return Err(npe(vm)),
    };
    if chunk.is_empty() {
        return Ok(JValue::Long(-1));
    }
    let n = chunk.len() as i64;
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.extend_from_slice(&chunk),
        _ => return Err(npe(vm)),
    }
    Ok(JValue::Long(n))
}

fn okio_buffer_write_byte(vm: &mut Vm, args: &[JValue]) -> R {
    let b = int_of(vm, args[1]) as u8;
    match payload_mut(vm, args[0]) {
        Some(Native::OkioBuf { bytes, .. }) => bytes.push(b),
        _ => return Err(npe(vm)),
    }
    Ok(args[0])
}

fn okio_buffer_read_byte(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    if *pos >= bytes.len() {
        return Err(NatErr::Throw(
            vm.throwable_of("Ljava/io/EOFException;", "end of buffer"),
        ));
    }
    let b = bytes[*pos];
    *pos += 1;
    Ok(JValue::Int(b as i8 as i32))
}

// wasm: additional BufferedSource/Buffer primitive read methods (ProtoBuf streams etc.).
fn okio_read_n(vm: &mut Vm, obj: JValue, n: usize) -> Result<Vec<u8>, NatErr> {
    let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, obj) else {
        return Err(npe(vm));
    };
    if *pos + n > bytes.len() {
        return Err(NatErr::Throw(
            vm.throwable_of("Ljava/io/EOFException;", "end of buffer"),
        ));
    }
    let out = bytes[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(out)
}
fn okio_read_int(vm: &mut Vm, args: &[JValue]) -> R {
    let b = okio_read_n(vm, args[0], 4)?;
    Ok(JValue::Int(i32::from_be_bytes([b[0], b[1], b[2], b[3]])))
}
fn okio_read_int_le(vm: &mut Vm, args: &[JValue]) -> R {
    let b = okio_read_n(vm, args[0], 4)?;
    Ok(JValue::Int(i32::from_le_bytes([b[0], b[1], b[2], b[3]])))
}
fn okio_read_long(vm: &mut Vm, args: &[JValue]) -> R {
    let b = okio_read_n(vm, args[0], 8)?;
    Ok(JValue::Long(i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
}
fn okio_read_long_le(vm: &mut Vm, args: &[JValue]) -> R {
    let b = okio_read_n(vm, args[0], 8)?;
    Ok(JValue::Long(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
}
fn okio_read_utf8_count(vm: &mut Vm, args: &[JValue]) -> R {
    let n = long_of(vm, args[1]).max(0) as usize;
    let b = okio_read_n(vm, args[0], n)?;
    let s = String::from_utf8_lossy(&b).into_owned();
    Ok(new_str(vm, &s))
}
fn okio_skip(vm: &mut Vm, args: &[JValue]) -> R {
    let n = long_of(vm, args[1]).max(0) as usize;
    let _ = okio_read_n(vm, args[0], n)?;
    Ok(JValue::Null)
}

// wasm: okio.Buffer$UnsafeCursor (fields: 0=buffer, 1=readWrite, 2=offset, 3=data, 4=start, 5=end).
fn okio_unsafe_cursor_init(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    let f = &mut vm.arena.objects[id as usize].fields;
    if f.len() >= 6 {
        f[0] = JValue::Null;
        f[1] = JValue::Int(0);
        f[2] = JValue::Long(-1);
        f[3] = JValue::Null;
        f[4] = JValue::Int(-1);
        f[5] = JValue::Int(-1);
    }
    Ok(JValue::Null)
}
fn okio_buffer_attach_cursor(vm: &mut Vm, buf: JValue, cursor: JValue, read_write: bool) -> R {
    let cur = if cursor.is_null_ref() {
        let c = alloc(vm, "Lokio/Buffer$UnsafeCursor;", Native::Opaque)?;
        okio_unsafe_cursor_init(vm, &[c])?;
        c
    } else {
        cursor
    };
    let JValue::Obj(id) = cur else {
        return Err(npe(vm));
    };
    let f = &mut vm.arena.objects[id as usize].fields;
    if f.len() >= 6 {
        f[0] = buf;
        f[1] = JValue::Int(i32::from(read_write));
        f[2] = JValue::Long(-1);
        f[3] = JValue::Null;
        f[4] = JValue::Int(-1);
        f[5] = JValue::Int(-1);
    }
    Ok(cur)
}
fn okio_buffer_read_and_write_unsafe_1(vm: &mut Vm, args: &[JValue]) -> R {
    okio_buffer_attach_cursor(vm, args[0], args[1], true)
}
fn okio_buffer_read_and_write_unsafe_0(vm: &mut Vm, args: &[JValue]) -> R {
    okio_buffer_attach_cursor(vm, args[0], JValue::Null, true)
}
fn okio_buffer_read_unsafe_1(vm: &mut Vm, args: &[JValue]) -> R {
    okio_buffer_attach_cursor(vm, args[0], args[1], false)
}
fn okio_buffer_read_unsafe_0(vm: &mut Vm, args: &[JValue]) -> R {
    okio_buffer_attach_cursor(vm, args[0], JValue::Null, false)
}
fn okio_unsafe_cursor_flush(vm: &mut Vm, id: u32) {
    let (buf, rw, data) = {
        let f = &vm.arena.objects[id as usize].fields;
        if f.len() < 6 {
            return;
        }
        (f[0], int_of(vm, f[1]) != 0, f[3])
    };
    if rw {
        if let Some(Native::Array(ArrayData::Byte(arr))) = payload(vm, data) {
            let updated: Vec<u8> = arr.iter().map(|&b| b as u8).collect();
            if let Some(Native::OkioBuf { bytes, pos }) = payload_mut(vm, buf) {
                let p = (*pos).min(bytes.len());
                bytes.truncate(p);
                bytes.extend_from_slice(&updated);
            }
        }
    }
}
fn okio_unsafe_cursor_seek(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    // wasm: flush any in-place edits made to cursor.data before seeking/terminating.
    okio_unsafe_cursor_flush(vm, id);
    let offset = long_of(vm, args[1]);
    let (buf, existing_data) = {
        let f = &vm.arena.objects[id as usize].fields;
        if f.len() < 6 {
            return Err(npe(vm));
        }
        (f[0], f[3])
    };
    let slice: Vec<i8> = match payload(vm, buf) {
        Some(Native::OkioBuf { bytes, pos }) => bytes[*pos..].iter().map(|&b| b as i8).collect(),
        _ => return Err(npe(vm)),
    };
    let len = slice.len();
    if offset < 0 || (offset as usize) >= len {
        let f = &mut vm.arena.objects[id as usize].fields;
        f[2] = JValue::Long(offset);
        f[3] = JValue::Null;
        f[4] = JValue::Int(-1);
        f[5] = JValue::Int(-1);
        return Ok(JValue::Int(-1));
    }
    let data = match payload(vm, existing_data) {
        Some(Native::Array(ArrayData::Byte(b))) if b.len() == len => existing_data,
        _ => alloc(vm, "[B", Native::Array(ArrayData::Byte(slice)))?,
    };
    let f = &mut vm.arena.objects[id as usize].fields;
    f[2] = JValue::Long(offset);
    f[3] = data;
    f[4] = JValue::Int(offset as i32);
    f[5] = JValue::Int(len as i32);
    Ok(JValue::Int((len - offset as usize) as i32))
}
fn okio_unsafe_cursor_next(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    let (cur_off, cur_end) = {
        let f = &vm.arena.objects[id as usize].fields;
        if f.len() < 6 {
            return Err(npe(vm));
        }
        (long_of(vm, f[2]), int_of(vm, f[5]))
    };
    let target = if cur_off == -1 { 0i64 } else { cur_end as i64 };
    okio_unsafe_cursor_seek(vm, &[args[0], JValue::Long(target)])
}
fn okio_unsafe_cursor_close(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    okio_unsafe_cursor_flush(vm, id);
    let f = &mut vm.arena.objects[id as usize].fields;
    if f.len() >= 6 {
        f[0] = JValue::Null;
        f[1] = JValue::Int(0);
        f[2] = JValue::Long(-1);
        f[3] = JValue::Null;
        f[4] = JValue::Int(-1);
        f[5] = JValue::Int(-1);
    }
    Ok(JValue::Null)
}

fn okio_buffer_output_stream(vm: &mut Vm, args: &[JValue]) -> R {
    let buffer = args[0].as_obj();
    alloc(
        vm,
        "Ljava/io/OutputStream;",
        Native::OkioOutputStream(buffer),
    )
}

pub(crate) const OKIO_TABLE: &[NativeEntry] = &[
    ne!(
        "Lokio/ByteString$Companion;",
        "decodeBase64",
        "(Ljava/lang/String;)Lokio/ByteString;",
        true,
        byte_string_decode_base64
    ),
    ne!(
        "Lokio/ByteString$Companion;",
        "encodeUtf8",
        "(Ljava/lang/String;)Lokio/ByteString;",
        true,
        byte_string_encode_utf8
    ),
    ne!(
        "Lokio/ByteString;",
        "hex",
        "()Ljava/lang/String;",
        true,
        byte_string_hex
    ),
    ne!("Lokio/ByteString;", "md5", "()Lokio/ByteString;", true, byte_string_md5),
    ne!("Lokio/ByteString;", "sha1", "()Lokio/ByteString;", true, byte_string_sha1),
    ne!("Lokio/ByteString;", "sha256", "()Lokio/ByteString;", true, byte_string_sha256),
    ne!("Lokio/ByteString;", "sha512", "()Lokio/ByteString;", true, byte_string_sha512),
    ne!(
        "Lokio/ByteString;",
        "toByteArray",
        "()[B",
        true,
        byte_string_to_byte_array
    ),
    ne!(
        "Lokio/ByteString;",
        "sha256",
        "()Lokio/ByteString;",
        true,
        byte_string_sha256
    ),
    ne!(
        "Lokio/ByteString;",
        "sha512",
        "()Lokio/ByteString;",
        true,
        byte_string_sha512
    ),
    ne!(
        "Lokio/ByteString;",
        "getByte",
        "(I)B",
        true,
        byte_string_get_byte
    ),
    ne!("Lokio/ByteString;", "size", "()I", true, byte_string_size),
    ne!(
        "Lokio/ByteString;",
        "utf8",
        "()Ljava/lang/String;",
        true,
        byte_string_utf8
    ),
    ne!(
        "Lokio/Okio;",
        "source",
        "(Ljava/io/InputStream;)Lokio/Source;",
        false,
        okio_source_input_stream
    ),
    ne!(
        "Lokio/Okio;",
        "source",
        "(Ljava/io/File;)Lokio/Source;",
        false,
        okio_source_file
    ),
    ne!(
        "Lokio/Okio;",
        "sink",
        "(Ljava/io/File;)Lokio/Sink;",
        false,
        okio_sink_file
    ),
    ne!(
        "Lokio/Okio;",
        "sink",
        "(Ljava/io/File;Z)Lokio/Sink;",
        false,
        okio_sink_file
    ),
    ne!(
        "Lokio/Okio;",
        "sink$default",
        "(Ljava/io/File;ZILjava/lang/Object;)Lokio/Sink;",
        false,
        okio_sink_file
    ),
    ne!(
        "Lokio/Okio;",
        "buffer",
        "(Lokio/Source;)Lokio/BufferedSource;",
        false,
        okio_buffer_source
    ),
    ne!(
        "Lokio/Okio;",
        "buffer",
        "(Lokio/Sink;)Lokio/BufferedSink;",
        false,
        okio_identity
    ),
    ne!(
        "Lokio/Okio;",
        "cipherSource",
        "(Lokio/Source;Ljavax/crypto/Cipher;)Lokio/CipherSource;",
        false,
        okio_cipher_source
    ),
    ne!(
        "Lokio/InflaterSource;",
        "<init>",
        "(Lokio/Source;Ljava/util/zip/Inflater;)V",
        true,
        okio_inflater_source_init
    ),
    ne!(
        "Lokio/ForwardingSource;",
        "<init>",
        "(Lokio/Source;)V",
        true,
        okio_forwarding_source_init
    ),
    ne!(
        "Lokio/ForwardingSource;",
        "read",
        "(Lokio/Buffer;J)J",
        true,
        okio_forwarding_source_read
    ),
    ne!(
        "Lokio/Buffer;",
        "writeAll",
        "(Lokio/Source;)J",
        true,
        okio_buffer_write_all
    ),
    ne!(
        "Lokio/Buffer;",
        "read",
        "(Lokio/Buffer;J)J",
        true,
        okio_buffer_read_into
    ),
    ne!(
        "Lokio/Buffer;",
        "writeByte",
        "(I)Lokio/Buffer;",
        true,
        okio_buffer_write_byte
    ),
    ne!(
        "Lokio/Buffer;",
        "readByte",
        "()B",
        true,
        okio_buffer_read_byte
    ),
    ne!(
        "Lokio/Buffer;",
        "write",
        "([BII)Lokio/Buffer;",
        true,
        okio_buffer_write_range
    ),
    ne!(
        "Lokio/Buffer;",
        "write",
        "([BII)Lokio/BufferedSink;",
        true,
        okio_buffer_write_range
    ),
    ne!(
        "Lokio/Buffer;",
        "writeUtf8",
        "(Ljava/lang/String;)Lokio/Buffer;",
        true,
        okio_buffer_write_utf8
    ),
    ne!(
        "Lokio/Buffer;",
        "writeIntLe",
        "(I)Lokio/Buffer;",
        true,
        okio_buffer_write_int_le
    ),
    ne!(
        "Lokio/Buffer;",
        "inputStream",
        "()Ljava/io/InputStream;",
        true,
        okio_buffer_input_stream
    ),
    ne!(
        "Lokio/ByteStreams;",
        "source",
        "(Ljava/io/InputStream;)Lokio/Source;",
        false,
        okio_source_input_stream
    ),
    ne!(
        "Lokio/ByteStreams;",
        "buffer",
        "(Lokio/Source;)Lokio/BufferedSource;",
        false,
        okio_buffer_source
    ),
    ne!(
        "Lokio/ByteStreamsKt;",
        "source",
        "(Ljava/io/InputStream;)Lokio/Source;",
        false,
        okio_source_input_stream
    ),
    ne!(
        "Lokio/ByteStreamsKt;",
        "buffer",
        "(Lokio/Source;)Lokio/BufferedSource;",
        false,
        okio_buffer_source
    ),
    ne!(
        "Lokio/BufferedSource;",
        "getBuffer",
        "()Lokio/Buffer;",
        true,
        okio_get_buffer
    ),
    ne!(
        "Lokio/BufferedSource;",
        "request",
        "(J)Z",
        true,
        okio_request
    ),
    ne!(
        "Lokio/BufferedSource;",
        "readByteArray",
        "()[B",
        true,
        okio_read_byte_array
    ),
    ne!(
        "Lokio/BufferedSource;",
        "readByteArray",
        "(J)[B",
        true,
        okio_read_byte_array_count
    ),
    ne!(
        "Lokio/BufferedSource;",
        "readUtf8",
        "()Ljava/lang/String;",
        true,
        okio_read_utf8
    ),
    ne!(
        "Lokio/BufferedSource;",
        "exhausted",
        "()Z",
        true,
        okio_exhausted
    ),
    // wasm:
    ne!(
        "Lokio/BufferedSource;",
        "readAll",
        "(Lokio/Sink;)J",
        true,
        okio_read_all
    ),
    ne!(
        "Lokio/Buffer;",
        "readAll",
        "(Lokio/Sink;)J",
        true,
        okio_read_all
    ),
    // wasm: primitive read methods on BufferedSource & Buffer (MANGA Plus ProtoBuf etc.).
    ne!("Lokio/BufferedSource;", "readByte", "()B", true, okio_buffer_read_byte),
    ne!("Lokio/BufferedSource;", "readInt", "()I", true, okio_read_int),
    ne!("Lokio/BufferedSource;", "readIntLe", "()I", true, okio_read_int_le),
    ne!("Lokio/BufferedSource;", "readLong", "()J", true, okio_read_long),
    ne!("Lokio/BufferedSource;", "readLongLe", "()J", true, okio_read_long_le),
    ne!("Lokio/BufferedSource;", "readUtf8", "(J)Ljava/lang/String;", true, okio_read_utf8_count),
    ne!("Lokio/BufferedSource;", "skip", "(J)V", true, okio_skip),
    ne!("Lokio/Buffer;", "readInt", "()I", true, okio_read_int),
    ne!("Lokio/Buffer;", "readIntLe", "()I", true, okio_read_int_le),
    ne!("Lokio/Buffer;", "readLong", "()J", true, okio_read_long),
    ne!("Lokio/Buffer;", "readLongLe", "()J", true, okio_read_long_le),
    ne!("Lokio/Buffer;", "readUtf8", "(J)Ljava/lang/String;", true, okio_read_utf8_count),
    ne!("Lokio/Buffer;", "skip", "(J)V", true, okio_skip),
    // wasm: Buffer$UnsafeCursor shims (MANGA Plus XOR image decryption etc.).
    ne!("Lokio/Buffer;", "readAndWriteUnsafe", "(Lokio/Buffer$UnsafeCursor;)Lokio/Buffer$UnsafeCursor;", true, okio_buffer_read_and_write_unsafe_1),
    ne!("Lokio/Buffer;", "readAndWriteUnsafe", "()Lokio/Buffer$UnsafeCursor;", true, okio_buffer_read_and_write_unsafe_0),
    ne!("Lokio/Buffer;", "readUnsafe", "(Lokio/Buffer$UnsafeCursor;)Lokio/Buffer$UnsafeCursor;", true, okio_buffer_read_unsafe_1),
    ne!("Lokio/Buffer;", "readUnsafe", "()Lokio/Buffer$UnsafeCursor;", true, okio_buffer_read_unsafe_0),
    ne!("Lokio/Buffer$UnsafeCursor;", "<init>", "()V", true, okio_unsafe_cursor_init),
    ne!("Lokio/Buffer$UnsafeCursor;", "seek", "(J)I", true, okio_unsafe_cursor_seek),
    ne!("Lokio/Buffer$UnsafeCursor;", "next", "()I", true, okio_unsafe_cursor_next),
    ne!("Lokio/Buffer$UnsafeCursor;", "close", "()V", true, okio_unsafe_cursor_close),
    ne!("Lokio/Buffer;", "get", "(J)B", true, okio_buffer_get),
    // wasm:
    ne!(
        "Lokio/Buffer;",
        "copyTo",
        "(Lokio/Buffer;JJ)Lokio/Buffer;",
        true,
        okio_buffer_copy_to
    ),
    ne!(
        "Lokio/Buffer;",
        "copyTo",
        "(Lokio/Buffer;)Lokio/Buffer;",
        true,
        okio_buffer_copy_to_all
    ),
    ne!(
        "Lokio/Buffer;",
        "copyTo$default",
        "(Lokio/Buffer;Lokio/Buffer;JJILjava/lang/Object;)Lokio/Buffer;",
        false,
        okio_buffer_copy_to_default
    ),
    ne!(
        "Lokio/Buffer;",
        "<init>",
        "()V",
        true,
        okio_buffer_init
    ),
    ne!(
        "Lokio/Buffer;",
        "readByteArray",
        "(J)[B",
        true,
        okio_read_byte_array_count
    ),
    ne!("Lokio/Buffer;", "getByte", "(J)B", true, okio_buffer_get),
    ne!("Lokio/Buffer;", "size", "()J", true, okio_buffer_size),
    ne!(
        "Lokio/Buffer;",
        "write",
        "([B)Lokio/Buffer;",
        true,
        okio_buffer_write
    ),
    ne!(
        "Lokio/Buffer;",
        "outputStream",
        "()Ljava/io/OutputStream;",
        true,
        okio_buffer_output_stream
    ),
    ne!(
        "Lokio/Buffer;",
        "readByteArray",
        "()[B",
        true,
        okio_read_byte_array
    ),
    ne!("Lokio/Buffer;", "close", "()V", true, okio_close),
    ne!("Lokio/Source;", "close", "()V", true, okio_close),
    ne!("Lokio/Sink;", "close", "()V", true, okio_close),
    ne!("Lokio/BufferedSink;", "close", "()V", true, okio_close),
    ne!("Lokio/BufferedSink;", "flush", "()V", true, okio_flush),
    ne!(
        "Lokio/BufferedSink;",
        "write",
        "([B)Lokio/BufferedSink;",
        true,
        okio_sink_write_bytes
    ),
    ne!(
        "Lokio/BufferedSink;",
        "write",
        "([BII)Lokio/BufferedSink;",
        true,
        okio_sink_write_bytes
    ),
    ne!(
        "Lokio/BufferedSink;",
        "writeUtf8",
        "(Ljava/lang/String;)Lokio/BufferedSink;",
        true,
        okio_sink_write_utf8
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Context;

    #[test]
    fn file_sink_writes_and_enforces_permission() {
        let data = std::fs::read("fixtures/classes.dex").unwrap();
        let mut ctx = Context::new(&data).unwrap();
        let vm = ctx.vm();
        let root = vm.cache_root_path().to_owned();
        let path = format!("{root}/out.bin");
        let file = alloc(vm, "Ljava/io/File;", Native::File { path: path.clone() }).unwrap();
        assert!(matches!(okio_sink_file(vm, &[file]), Err(NatErr::Throw(_))));

        vm.perms
            .grant(Permission::Filesystem(FilesystemPermission::Path(
                root.clone(),
            )));
        std::fs::create_dir_all(&root).unwrap();
        let sink = okio_sink_file(vm, &[file]).unwrap();
        let bytes = vec![1_i8, 2, -1];
        let input = alloc_arr(vm, "B", bytes.len(), move || ArrayData::Byte(bytes)).unwrap();
        okio_sink_write_bytes(vm, &[sink, input]).unwrap();
        okio_close(vm, &[sink]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![1, 2, 255]);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}


