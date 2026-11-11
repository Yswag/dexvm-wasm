//! `java.time.temporal.ChronoField` constants. Each is a plain `Native::Str`
//! carrying the field name; the `get(...)` shims read it back.

use crate::vm::native::*;

macro_rules! chrono_field {
    ($name:ident, $tag:expr) => {
        pub(crate) fn $name(vm: &mut Vm) -> JValue {
            let Ok(class) = vm.ensure_class_by_desc("Ljava/time/temporal/ChronoField;") else {
                return JValue::Null;
            };
            JValue::Obj(
                vm.arena
                    .alloc(class, Vec::new(), Some(Native::Str($tag.into()))),
            )
        }
    };
}

chrono_field!(nano_of_second, "NANO_OF_SECOND");
chrono_field!(second_of_minute, "SECOND_OF_MINUTE");
chrono_field!(minute_of_hour, "MINUTE_OF_HOUR");
chrono_field!(hour_of_day, "HOUR_OF_DAY");
chrono_field!(day_of_week, "DAY_OF_WEEK");
chrono_field!(day_of_month, "DAY_OF_MONTH");
chrono_field!(day_of_year, "DAY_OF_YEAR");
chrono_field!(month_of_year, "MONTH_OF_YEAR");
chrono_field!(year, "YEAR");
chrono_field!(epoch_day, "EPOCH_DAY");

pub(crate) const TABLE: &[NativeEntry] = &[];
