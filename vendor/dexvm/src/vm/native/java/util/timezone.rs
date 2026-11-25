//! java.util.TimeZone host shims.

use crate::vm::native::*;

pub(crate) fn time_zone_get_time_zone(vm: &mut Vm, args: &[JValue]) -> R {
    let id = jstr(vm, args[0])?;
    alloc(vm, "Ljava/util/TimeZone;", Native::TimeZone(id))
}

pub(crate) fn time_zone_get_default(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Ljava/util/TimeZone;",
        Native::TimeZone("UTC".to_string()),
    )
}

// wasm:
fn tz_id_of(vm: &Vm, v: JValue) -> Option<String> {
    match payload(vm, v) {
        Some(Native::TimeZone(id)) => Some(id.clone()),
        _ => None,
    }
}

// wasm: parse offset in milliseconds for common TimeZone IDs (GMT±HH:MM, UTC, major zones).
fn tz_offset_ms(id: &str) -> i32 {
    const HOUR_MS: i32 = 3_600_000;
    const MIN_MS: i32 = 60_000;
    let s = id.trim();
    if s.eq_ignore_ascii_case("UTC") || s.eq_ignore_ascii_case("GMT") || s == "Z" {
        return 0;
    }
    if let Some(rest) = s
        .strip_prefix("GMT")
        .or_else(|| s.strip_prefix("UTC"))
        .or_else(|| if s.starts_with('+') || s.starts_with('-') { Some(s) } else { None })
    {
        if let Some(sign) = rest.chars().next().and_then(|c| match c {
            '+' => Some(1),
            '-' => Some(-1),
            _ => None,
        }) {
            let body = &rest[1..];
            let (h, m) = if let Some((hs, ms)) = body.split_once(':') {
                (hs.parse::<i32>().ok(), ms.parse::<i32>().ok())
            } else if body.len() == 4 {
                (body[..2].parse::<i32>().ok(), body[2..].parse::<i32>().ok())
            } else {
                (body.parse::<i32>().ok(), Some(0))
            };
            if let (Some(hh), Some(mm)) = (h, m) {
                return sign * (hh * HOUR_MS + mm * MIN_MS);
            }
        }
    }
    match s {
        "Asia/Shanghai" | "Asia/Chongqing" | "Asia/Hong_Kong" | "Asia/Taipei" | "Asia/Singapore" | "PRC" | "CTT" => 8 * HOUR_MS,
        "Asia/Tokyo" | "Asia/Seoul" | "JST" | "KST" => 9 * HOUR_MS,
        "Asia/Ho_Chi_Minh" | "Asia/Saigon" | "Asia/Bangkok" | "Asia/Jakarta" => 7 * HOUR_MS,
        "Europe/Moscow" => 3 * HOUR_MS,
        "Europe/Berlin" | "Europe/Paris" | "CET" => HOUR_MS,
        "America/New_York" | "EST" => -5 * HOUR_MS,
        "America/Chicago" | "CST" => -6 * HOUR_MS,
        "America/Denver" | "MST" => -7 * HOUR_MS,
        "America/Los_Angeles" | "PST" => -8 * HOUR_MS,
        _ => 0,
    }
}

// wasm:
pub(crate) fn time_zone_get_id(vm: &mut Vm, args: &[JValue]) -> R {
    let id = tz_id_of(vm, args[0]).ok_or_else(|| npe(vm))?;
    Ok(new_str(vm, &id))
}

// wasm:
pub(crate) fn time_zone_get_raw_offset(vm: &mut Vm, args: &[JValue]) -> R {
    let id = tz_id_of(vm, args[0]).ok_or_else(|| npe(vm))?;
    Ok(JValue::Int(tz_offset_ms(&id)))
}

// wasm:
pub(crate) fn time_zone_to_zone_id(vm: &mut Vm, args: &[JValue]) -> R {
    let _ = tz_id_of(vm, args[0]).ok_or_else(|| npe(vm))?;
    alloc(vm, "Ljava/time/ZoneId;", Native::Opaque)
}

/// Native methods for Ljava/util/TimeZone;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/util/TimeZone;",
        "getTimeZone",
        "(Ljava/lang/String;)Ljava/util/TimeZone;",
        false,
        time_zone_get_time_zone
    ),
    ne!(
        "Ljava/util/TimeZone;",
        "getDefault",
        "()Ljava/util/TimeZone;",
        false,
        time_zone_get_default
    ),
    // wasm:
    ne!(
        "Ljava/util/TimeZone;",
        "getID",
        "()Ljava/lang/String;",
        true,
        time_zone_get_id
    ),
    // wasm:
    ne!(
        "Ljava/util/TimeZone;",
        "getDisplayName",
        "()Ljava/lang/String;",
        true,
        time_zone_get_id
    ),
    // wasm:
    ne!(
        "Ljava/util/TimeZone;",
        "getRawOffset",
        "()I",
        true,
        time_zone_get_raw_offset
    ),
    // wasm:
    ne!(
        "Ljava/util/TimeZone;",
        "getOffset",
        "(J)I",
        true,
        time_zone_get_raw_offset
    ),
    // wasm:
    ne!(
        "Ljava/util/TimeZone;",
        "toZoneId",
        "()Ljava/time/ZoneId;",
        true,
        time_zone_to_zone_id
    ),
];
