//! java.time host shims.

use crate::vm::native::*;

mod chrono_unit;
mod chrono_field;
mod date_time_formatter;
mod date_time_formatter_builder;
mod instant;
mod local_date;
mod local_date_time;
mod zone_id;
mod zone_offset;
mod zoned_date_time;

pub(crate) use chrono_unit::{
    days as lazy_chrono_unit_days, hours as lazy_chrono_unit_hours,
    millis as lazy_chrono_unit_millis, minutes as lazy_chrono_unit_minutes,
    months as lazy_chrono_unit_months, seconds as lazy_chrono_unit_seconds,
    weeks as lazy_chrono_unit_weeks, years as lazy_chrono_unit_years,
};
pub(crate) use date_time_formatter::{
    lazy_basic_iso_date, lazy_iso_instant, lazy_iso_local_date, lazy_iso_local_date_time,
    lazy_iso_local_time, lazy_iso_offset_date, lazy_iso_offset_date_time, lazy_iso_offset_time,
    lazy_iso_ordinal_date, lazy_iso_week_date, lazy_iso_zoned_date_time, lazy_rfc_1123_date_time,
};
pub(crate) use zone_offset::utc as lazy_zone_offset_utc;
pub(crate) use chrono_field::{
    day_of_month as lazy_chrono_field_day_of_month,
    day_of_week as lazy_chrono_field_day_of_week, day_of_year as lazy_chrono_field_day_of_year,
    epoch_day as lazy_chrono_field_epoch_day, hour_of_day as lazy_chrono_field_hour_of_day,
    minute_of_hour as lazy_chrono_field_minute_of_hour, month_of_year as lazy_chrono_field_month_of_year,
    nano_of_second as lazy_chrono_field_nano_of_second,
    second_of_minute as lazy_chrono_field_second_of_minute, year as lazy_chrono_field_year,
};

/// All java.time native tables, grouped for `register`.
pub(crate) const TIME_TABLE: &[&[NativeEntry]] = &[
    date_time_formatter::TABLE,
    date_time_formatter_builder::TABLE,
    zone_id::TABLE,
    zone_offset::TABLE,
    chrono_field::TABLE,
    local_date::TABLE,
    local_date_time::TABLE,
    zoned_date_time::TABLE,
    instant::TABLE,
];
