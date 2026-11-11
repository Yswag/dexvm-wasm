//! java.time.format.DateTimeFormatter host shims: DateTimeFormatter.ofPattern
//! + Locale.ROOT.

use crate::vm::native::*;

pub(crate) fn dtf_of_pattern(vm: &mut Vm, args: &[JValue]) -> R {
    let pattern = jstr(vm, args[0])?;
    alloc(
        vm,
        "Ljava/time/format/DateTimeFormatter;",
        Native::DateFormatter {
            pattern,
            zone: String::new(),
        },
    )
}

pub(crate) fn dtf_tostring(vm: &mut Vm, args: &[JValue]) -> R {
    let pattern = match payload(vm, args[0]) {
        Some(Native::DateFormatter { pattern, .. }) => pattern.clone(),
        _ => return Err(npe(vm)),
    };
    Ok(new_str(vm, &pattern))
}

/// wasm: `parseCaseInsensitive()` is a no-op for the ASCII, fixed-pattern
/// formatter — return `this` so callers can chain.
pub(crate) fn dtf_parse_case_insensitive(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}

/// `withLocale` doesn't affect this simplified (ASCII, fixed-pattern)
/// formatter — returns `this` for chaining.
pub(crate) fn dtf_with_locale(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}

pub(crate) fn dtf_of_localized_date(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Ljava/time/format/DateTimeFormatter;",
        Native::DateFormatter {
            pattern: "yyyy-MM-dd".to_string(),
            zone: String::new(),
        },
    )
}

pub(crate) fn dtf_format(vm: &mut Vm, args: &[JValue]) -> R {
    let pattern = match payload(vm, args[0]) {
        Some(Native::DateFormatter { pattern, .. }) => pattern.clone(),
        _ => return Err(npe(vm)),
    };
    let millis = match payload(vm, args[1]) {
        Some(Native::EpochMillis(m)) => *m,
        Some(Native::LocalDay(d)) => i64::from(*d) * super::super::civil::DAY_MS,
        Some(Native::Date(m)) => *m,
        _ => return Err(npe(vm)),
    };
    let (year, month, day, hour, minute, second, _) = super::super::civil::components(millis);
    let mut out = String::new();
    let pb = pattern.as_bytes();
    let mut pi = 0;
    while pi < pb.len() {
        let c = pb[pi];
        if c == b'\'' {
            pi += 1;
            while pi < pb.len() && pb[pi] != b'\'' {
                out.push(pb[pi] as char);
                pi += 1;
            }
            pi += 1;
            continue;
        }
        let mut run = 1;
        while pi + run < pb.len() && pb[pi + run] == c {
            run += 1;
        }
        match c {
            b'y' | b'Y' => out.push_str(&format!("{:0width$}", year, width = run.max(4))),
            b'M' => out.push_str(&format!("{:0width$}", month, width = run)),
            b'd' => out.push_str(&format!("{:0width$}", day, width = run)),
            b'H' => out.push_str(&format!("{:0width$}", hour, width = run)),
            b'm' => out.push_str(&format!("{:0width$}", minute, width = run)),
            b's' => out.push_str(&format!("{:0width$}", second, width = run)),
            _ => {
                for _ in 0..run {
                    out.push(c as char);
                }
            }
        }
        pi += run;
    }
    Ok(new_str(vm, &out))
}

/// wasm: materializer for the JDK's predefined formatter constants; 1.6
/// sources read `DateTimeFormatter.ISO_LOCAL_DATE` & co. as static fields.
fn dtf_pattern(vm: &mut Vm, pattern: &str) -> JValue {
    alloc(
        vm,
        "Ljava/time/format/DateTimeFormatter;",
        Native::DateFormatter {
            pattern: pattern.to_string(),
            zone: String::new(),
        },
    )
    .unwrap_or(JValue::Null)
}

pub(crate) fn lazy_iso_local_date(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-MM-dd")
}
pub(crate) fn lazy_iso_local_time(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "HH:mm:ss")
}
pub(crate) fn lazy_iso_local_date_time(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-MM-dd'T'HH:mm:ss")
}
pub(crate) fn lazy_iso_offset_date(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-MM-ddXXX")
}
pub(crate) fn lazy_iso_offset_time(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "HH:mm:ssXXX")
}
pub(crate) fn lazy_iso_offset_date_time(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-MM-dd'T'HH:mm:ssXXX")
}
pub(crate) fn lazy_iso_zoned_date_time(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-MM-dd'T'HH:mm:ssXXX'['VV']'")
}
pub(crate) fn lazy_iso_instant(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-MM-dd'T'HH:mm:ssX")
}
pub(crate) fn lazy_basic_iso_date(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyyMMdd")
}
pub(crate) fn lazy_iso_ordinal_date(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "yyyy-DDD")
}
pub(crate) fn lazy_iso_week_date(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "YYYY-'W'ww-e")
}
pub(crate) fn lazy_rfc_1123_date_time(vm: &mut Vm) -> JValue {
    dtf_pattern(vm, "EEE, dd MMM yyyy HH:mm:ss zzz")
}

/// `DateTimeFormatter.withZone(zone)` — chaining no-op; the pattern is kept.
fn dtf_with_zone(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}

/// `DateTimeFormatter.getZone()`. The fixed-offset model carries no real
/// zone, so hand back a plain `ZoneId` tagged "Z".
fn dtf_get_zone(vm: &mut Vm, _args: &[JValue]) -> R {
    let Ok(class) = vm.ensure_class_by_desc("Ljava/time/ZoneId;") else {
        return Err(npe(vm));
    };
    Ok(JValue::Obj(
        vm.arena.alloc(class, Vec::new(), Some(Native::Str("Z".into()))),
    ))
}

/// Native methods for Ljava/time/format/DateTimeFormatter;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "ofPattern",
        "(Ljava/lang/String;Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;",
        false,
        dtf_of_pattern
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "parseCaseInsensitive",
        "()Ljava/time/format/DateTimeFormatter;",
        true,
        dtf_parse_case_insensitive
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "toString",
        "()Ljava/lang/String;",
        true,
        dtf_tostring
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "withLocale",
        "(Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;",
        true,
        dtf_with_locale
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "ofLocalizedDate",
        "(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;",
        false,
        dtf_of_localized_date
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "format",
        "(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;",
        true,
        dtf_format
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "withZone",
        "(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;",
        true,
        dtf_with_zone
    ),
    ne!(
        "Ljava/time/format/DateTimeFormatter;",
        "getZone",
        "()Ljava/time/ZoneId;",
        true,
        dtf_get_zone
    ),
];
