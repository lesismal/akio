//! Recognising a `&str` behind a generic `T` (ADR-081 update).
//!
//! `akio-http`'s `text(status, body: impl Into<String>)` is mostly called with a `&str`, which
//! std turns into a new `String`: one allocation per response. With [`as_str`] it sees the
//! `&str` and copies it into a buffer it reuses per thread instead; every other type goes
//! through `Into<String>` as before.
//!
//! Telling a `&'a str` apart needs the type's identity without a `'static` bound, which
//! `std::any` does not offer: [`type_id`] is `typeid::of` (erased-serde's technique), and the
//! only `unsafe` here.
//!
//! `#[doc(hidden)]`: for `akio-http`; outside the stability promise.
#![allow(unsafe_code)]

use std::any::TypeId;
use std::marker::PhantomData;

/// The `TypeId` of `T` with its lifetimes erased; `T` need not be `'static`.
#[inline(always)]
fn type_id<T: ?Sized>() -> TypeId {
    trait NonStaticAny {
        fn get_type_id(&self) -> TypeId
        where
            Self: 'static;
    }
    impl<T: ?Sized> NonStaticAny for PhantomData<T> {
        #[inline(always)]
        fn get_type_id(&self) -> TypeId
        where
            Self: 'static,
        {
            TypeId::of::<T>()
        }
    }
    let p = PhantomData::<T>;
    // SAFETY: only the trait object's lifetime bound is extended. Nothing of `T` is reachable
    // through it (`PhantomData` holds no value), and `TypeId::of` does not depend on lifetimes
    // (they are erased before code generation), so the call cannot observe a dangling borrow.
    let any =
        unsafe { std::mem::transmute::<&dyn NonStaticAny, &(dyn NonStaticAny + 'static)>(&p) };
    any.get_type_id()
}

/// `v` as a `&str` when `T` is `&str` (for any lifetime), else `None`.
#[inline(always)]
pub fn as_str<'v, T>(v: &'v T) -> Option<&'v str> {
    if type_id::<T>() == TypeId::of::<&'static str>() {
        // SAFETY: `T` is `&'a str` for some `'a` (type identity up to lifetimes), so `v` points
        // to a valid `&'a str`; `&'v T` being well-formed means `'a: 'v`, so the copied
        // reference is valid for `'v`.
        Some(unsafe { *std::ptr::from_ref(v).cast::<&'v str>() })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_str_of_any_lifetime() {
        let owned = String::from("local");
        let s: &str = &owned;
        assert_eq!(as_str(&s), Some("local"));
        assert_eq!(as_str(&"static"), Some("static"));
        assert_eq!(as_str(&""), Some(""));
        assert_eq!(as_str(&owned), None);
        assert_eq!(as_str(&&owned), None);
        assert_eq!(as_str(&&"twice"), None);
        assert_eq!(as_str(&'c'), None);
        assert_eq!(as_str(&Box::<str>::from("b")), None);
        assert_eq!(as_str(&std::borrow::Cow::Borrowed("cow")), None);
        let mut m = String::from("mut");
        assert_eq!(as_str(&m.as_mut_str()), None);
        // A `&str` held by a value that does not outlive the call.
        let short = String::from("short-lived");
        let got = {
            let r: &str = &short[..5];
            as_str(&r).map(str::to_owned)
        };
        assert_eq!(got.as_deref(), Some("short"));
    }
}
