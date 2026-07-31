//! Contract tests for MemShadow readiness error typing.
//!
//! `memshadow_ready_or_block_if_idle` previously returned `Result<&MemShadow,
//! &'static str>`; routes matched raw strings ("building"/"error"). The
//! typed contract: the error is a `MemShadowError` enum whose string form is
//! stable (routes serialize it into the response `status` field unchanged),
//! so AI consumers see identical JSON while the server side gets real
//! exhaustiveness checking.

use tracemiku_core::memshadow::MemShadowError;

#[test]
fn memshadow_error_kind_matches_legacy_status_strings() {
    // These strings are the committed wire contract (routes put them in the
    // `status` field of their responses). The typed enum must round-trip to
    // exactly these values.
    for (kind, expected) in [
        (MemShadowError::Building, "loading"),
        (MemShadowError::Failed, "error"),
    ] {
        assert_eq!(kind.status_str(), expected);
    }
}

#[test]
fn memshadow_error_is_exhaustive() {
    // Compile-time check: constructing both variants proves the enum exists
    // with the intended shape; a match without _ is exhaustive by the
    // compiler when this compiles.
    let _ = match MemShadowError::Building {
        MemShadowError::Building => (),
        MemShadowError::Failed => (),
    };
}
