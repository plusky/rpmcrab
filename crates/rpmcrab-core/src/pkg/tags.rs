//! Tag-reading helpers over librpm's `PackageHeader`, replicating rpmlint's
//! `byte_to_string` and empty-list-to-`None` semantics (`rpmlint/pkg.py`).

use librpm::{OwnedTagData, PackageHeader, Tag};

/// Read a STRING_ARRAY tag as `Vec<String>`. librpm decodes a single-element
/// STRING_ARRAY as a bare `Str`, so accept both (the `*PROG` scriptlet quirk).
pub fn str_array(header: &PackageHeader, tag: Tag) -> Vec<String> {
    match header.get_owned(tag) {
        Some(OwnedTagData::StrArray(v)) => v,
        Some(OwnedTagData::Str(s)) => vec![s],
        Some(OwnedTagData::I18NStr(v)) => v,
        _ => Vec::new(),
    }
}

/// Read a scalar string tag; for an I18N table returns the first locale (what
/// rpmlint's low-level access yields). A present-but-empty tag is `Some("")`
/// (rpmlint returns `''`); only an absent tag is `None`.
pub fn str_tag(header: &PackageHeader, tag: Tag) -> Option<String> {
    match header.get_owned(tag) {
        Some(OwnedTagData::Str(s)) => Some(s),
        Some(OwnedTagData::StrArray(v)) => v.into_iter().next(),
        Some(OwnedTagData::I18NStr(v)) => v.into_iter().next(),
        _ => None,
    }
}

/// Read an INT32 array tag; empty when absent.
pub fn int32_array(header: &PackageHeader, tag: Tag) -> Vec<i32> {
    header
        .get_owned(tag)
        .and_then(|d| d.as_int32_array().map(<[i32]>::to_vec))
        .unwrap_or_default()
}

/// Read an INT16 array tag; empty when absent.
pub fn int16_array(header: &PackageHeader, tag: Tag) -> Vec<i16> {
    header
        .get_owned(tag)
        .and_then(|d| d.as_int16_array().map(<[i16]>::to_vec))
        .unwrap_or_default()
}
