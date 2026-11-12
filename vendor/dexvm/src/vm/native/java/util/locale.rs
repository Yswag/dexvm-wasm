use crate::vm::native::*;

pub fn lazy_opaque_locale(vm: &mut Vm) -> JValue {
    let Ok(class) = vm.ensure_class_by_desc("Ljava/util/Locale;") else {
        return JValue::Null;
    };
    JValue::Obj(vm.arena.alloc(class, Vec::new(), Some(Native::Opaque)))
}

// Locale constants (e.g. Locale.US) used by `String.lowercase(Locale)` etc.
macro_rules! locale_const {
    ($name:ident, $tag:expr) => {
        pub fn $name(vm: &mut Vm) -> JValue {
            let Ok(class) = vm.ensure_class_by_desc("Ljava/util/Locale;") else {
                return JValue::Null;
            };
            JValue::Obj(
                vm.arena
                    .alloc(class, Vec::new(), Some(Native::Str($tag.into()))),
            )
        }
    };
}
locale_const!(lazy_locale_us, "en-US");
locale_const!(lazy_locale_uk, "en-GB");
locale_const!(lazy_locale_canada, "en-CA");
locale_const!(lazy_locale_japan, "ja-JP");
locale_const!(lazy_locale_korea, "ko-KR");
locale_const!(lazy_locale_china, "zh-CN");
locale_const!(lazy_locale_france, "fr-FR");
locale_const!(lazy_locale_germany, "de-DE");
locale_const!(lazy_locale_italy, "it-IT");

// java.util.Locale host shims.

// java.util.Locale
// ---------------------------------------------------------------------------

pub(crate) fn locale_get_default(vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(lazy_opaque_locale(vm))
}

pub(crate) fn locale_init(vm: &mut Vm, args: &[JValue]) -> R {
    let tag = if args.len() > 1 {
        jstr(vm, args[1])?
    } else {
        String::new()
    };
    let Some(n) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    match n {
        Native::Str(dst) => *dst = tag,
        _ => *n = Native::Str(tag),
    }
    Ok(JValue::Null)
}

pub(crate) fn locale_tag(vm: &mut Vm, v: JValue) -> String {
    match payload(vm, v) {
        Some(Native::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

pub(crate) fn locale_to_string(vm: &mut Vm, args: &[JValue]) -> R {
    let tag = locale_tag(vm, args[0]);
    Ok(new_str(vm, &tag))
}

pub(crate) fn locale_get_language(vm: &mut Vm, args: &[JValue]) -> R {
    let lang = locale_tag(vm, args[0])
        .split(['_', '-'])
        .next()
        .unwrap_or("")
        .to_string();
    Ok(new_str(vm, &lang))
}

pub(crate) fn locale_get_country(vm: &mut Vm, args: &[JValue]) -> R {
    let tag = locale_tag(vm, args[0]);
    let mut parts = tag.split(['_', '-']);
    let _lang = parts.next();
    Ok(new_str(vm, parts.next().unwrap_or("")))
}

pub(crate) fn locale_for_language_tag(vm: &mut Vm, args: &[JValue]) -> R {
    let tag = jstr(vm, args[0])?;
    alloc(vm, "Ljava/util/Locale;", Native::Str(tag))
}

pub(crate) fn locale_to_language_tag(vm: &mut Vm, args: &[JValue]) -> R {
    let tag = locale_tag(vm, args[0]).replace('_', "-");
    Ok(new_str(vm, &tag))
}

fn locale_builder_segments(vm: &Vm, v: JValue) -> Option<Vec<String>> {
    match payload(vm, v) {
        Some(Native::Str(s)) => Some(s.split('\u{1f}').map(str::to_string).collect()),
        _ => None,
    }
}

fn locale_builder_init(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    let Some(object) = vm.arena.objects.get_mut(id as usize) else {
        return Err(npe(vm));
    };
    object.native = Some(Native::Str("\u{1f}\u{1f}\u{1f}".into()));
    Ok(JValue::Null)
}

fn locale_builder_set(vm: &mut Vm, args: &[JValue], slot: usize) -> R {
    let value = jstr(vm, args[1])?;
    let mut parts = locale_builder_segments(vm, args[0]).ok_or_else(|| npe(vm))?;
    while parts.len() < 4 {
        parts.push(String::new());
    }
    parts[slot] = value;
    let Some(Native::Str(s)) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *s = parts.join("\u{1f}");
    Ok(args[0])
}

pub(crate) fn locale_builder_set_language(vm: &mut Vm, args: &[JValue]) -> R {
    locale_builder_set(vm, args, 0)
}
pub(crate) fn locale_builder_set_script(vm: &mut Vm, args: &[JValue]) -> R {
    locale_builder_set(vm, args, 1)
}
pub(crate) fn locale_builder_set_region(vm: &mut Vm, args: &[JValue]) -> R {
    locale_builder_set(vm, args, 2)
}
pub(crate) fn locale_builder_set_variant(vm: &mut Vm, args: &[JValue]) -> R {
    locale_builder_set(vm, args, 3)
}

pub(crate) fn locale_builder_build(vm: &mut Vm, args: &[JValue]) -> R {
    let parts = locale_builder_segments(vm, args[0]).ok_or_else(|| npe(vm))?;
    let mut tag = parts.first().cloned().unwrap_or_default();
    for part in parts.iter().skip(1) {
        if !part.is_empty() {
            tag.push('-');
            tag.push_str(part);
        }
    }
    alloc(vm, "Ljava/util/Locale;", Native::Str(tag))
}

/// Native methods for Ljava/util/Locale;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/util/Locale;",
        "<init>",
        "(Ljava/lang/String;)V",
        true,
        locale_init
    ),
    ne!(
        "Ljava/util/Locale;",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        true,
        locale_init
    ),
    ne!(
        "Ljava/util/Locale;",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        true,
        locale_init
    ),
    ne!(
        "Ljava/util/Locale;",
        "getDefault",
        "()Ljava/util/Locale;",
        false,
        locale_get_default
    ),
    ne!(
        "Ljava/util/Locale;",
        "toString",
        "()Ljava/lang/String;",
        true,
        locale_to_string
    ),
    ne!(
        "Ljava/util/Locale;",
        "getLanguage",
        "()Ljava/lang/String;",
        true,
        locale_get_language
    ),
    ne!(
        "Ljava/util/Locale;",
        "getCountry",
        "()Ljava/lang/String;",
        true,
        locale_get_country
    ),
    ne!(
        "Ljava/util/Locale;",
        "forLanguageTag",
        "(Ljava/lang/String;)Ljava/util/Locale;",
        false,
        locale_for_language_tag
    ),
    ne!(
        "Ljava/util/Locale;",
        "getDisplayLanguage",
        "()Ljava/lang/String;",
        true,
        locale_get_language
    ),
    ne!(
        "Ljava/util/Locale;",
        "getDisplayLanguage",
        "(Ljava/util/Locale;)Ljava/lang/String;",
        true,
        locale_get_language
    ),
    ne!(
        "Ljava/util/Locale;",
        "getDisplayName",
        "(Ljava/util/Locale;)Ljava/lang/String;",
        true,
        locale_to_string
    ),
    ne!(
        "Ljava/util/Locale;",
        "toLanguageTag",
        "()Ljava/lang/String;",
        true,
        locale_to_language_tag
    ),
    ne!(
        "Ljava/util/Locale$Builder;",
        "<init>",
        "()V",
        true,
        locale_builder_init
    ),
    ne!(
        "Ljava/util/Locale$Builder;",
        "setLanguage",
        "(Ljava/lang/String;)Ljava/util/Locale$Builder;",
        true,
        locale_builder_set_language
    ),
    ne!(
        "Ljava/util/Locale$Builder;",
        "setScript",
        "(Ljava/lang/String;)Ljava/util/Locale$Builder;",
        true,
        locale_builder_set_script
    ),
    ne!(
        "Ljava/util/Locale$Builder;",
        "setRegion",
        "(Ljava/lang/String;)Ljava/util/Locale$Builder;",
        true,
        locale_builder_set_region
    ),
    ne!(
        "Ljava/util/Locale$Builder;",
        "setVariant",
        "(Ljava/lang/String;)Ljava/util/Locale$Builder;",
        true,
        locale_builder_set_variant
    ),
    ne!(
        "Ljava/util/Locale$Builder;",
        "build",
        "()Ljava/util/Locale;",
        true,
        locale_builder_build
    ),
];
