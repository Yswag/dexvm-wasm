use crate::vm::native::*;

pub(crate) mod civil;
mod io;
mod lang;
mod math;
mod net;
mod nio;
mod security;
mod text;
mod r#time;
mod util;

pub(crate) mod javax_crypto;

pub(crate) use self::io::*;
pub(crate) use self::nio::*;
pub(crate) use civil::components as civil_components;
pub(crate) use math::lazy_rounding_mode;
pub(crate) use lang::*;
pub(crate) use r#time::{
    lazy_chrono_unit_days, lazy_chrono_unit_hours, lazy_chrono_unit_millis,
    lazy_chrono_unit_minutes, lazy_chrono_unit_months, lazy_chrono_unit_seconds,
    lazy_chrono_unit_weeks, lazy_chrono_unit_years,
    lazy_basic_iso_date, lazy_iso_instant, lazy_iso_local_date, lazy_iso_local_date_time,
    lazy_iso_local_time, lazy_iso_offset_date, lazy_iso_offset_date_time, lazy_iso_offset_time,
    lazy_iso_ordinal_date, lazy_iso_week_date, lazy_iso_zoned_date_time,
    lazy_rfc_1123_date_time,
};
pub(crate) use r#time::lazy_zone_offset_utc;
pub(crate) use r#time::{
    lazy_chrono_field_day_of_month, lazy_chrono_field_day_of_week, lazy_chrono_field_day_of_year,
    lazy_chrono_field_epoch_day, lazy_chrono_field_hour_of_day,
    lazy_chrono_field_minute_of_hour, lazy_chrono_field_month_of_year,
    lazy_chrono_field_nano_of_second, lazy_chrono_field_second_of_minute, lazy_chrono_field_year,
};
pub(crate) use text::*;
pub(crate) use util::*;

/// Collect every java.* native table for `register`.
pub(crate) fn java_tables(out: &mut Vec<&'static [NativeEntry]>) {
    out.extend(lang::LANG_TABLE.iter().copied());
    out.extend(math::MATH_TABLE.iter().copied());
    out.extend(io::IO_TABLE.iter().copied());
    #[cfg(feature = "android")]
    out.extend(io::FILE_TABLE.iter().copied());
    out.extend(net::NET_TABLE.iter().copied());
    out.extend(nio::NIO_TABLE.iter().copied());
    out.extend(security::SECURITY_TABLE.iter().copied());
    out.push(javax_crypto::JAVAX_CRYPTO_TABLE);
    out.extend(text::TEXT_TABLE.iter().copied());
    out.extend(r#time::TIME_TABLE.iter().copied());
    out.extend(util::UTIL_TABLE.iter().copied());
}
