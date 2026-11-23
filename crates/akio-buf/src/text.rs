//! Text bodies in pooled buffers (ADR-081 update).
//!
//! `akio-http`'s `text(status, body: impl Into<String>)` is mostly called with a `&str`, which
//! std turns into a new `String`: one allocation per response. [`into_bytes`] recognises a
//! `&str` behind the generic and copies it into a pool buffer ([`get`](crate::get)) instead; the
//! server gives the buffer back ([`put`](crate::put)) once the body is copied into the
//! response's output. Every other type goes through `Into<String>` as before.
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

/// The bytes of `v`: a `&str` copied into a pool buffer (empty: no buffer), anything else
/// through `Into<String>`.
#[inline]
pub fn into_bytes<T: Into<String>>(v: T) -> Vec<u8> {
    if let Some(s) = as_str(&v) {
        if s.is_empty() {
            return Vec::new();
        }
        let mut b = crate::get(s.len());
        b.extend_from_slice(s.as_bytes());
        return b;
    }
    v.into().into_bytes()
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
        assert_eq!(as_str(&owned), None);
        assert_eq!(as_str(&&owned), None);
        assert_eq!(as_str(&'c'), None);
        assert_eq!(as_str(&Box::<str>::from("b")), None);
        let mut m = String::from("mut");
        assert_eq!(as_str(&m.as_mut_str()), None);
    }

    #[test]
    fn str_bodies_come_from_the_pool() {
        let b = into_bytes("Hello, World!");
        assert_eq!(b, b"Hello, World!");
        assert_eq!(b.capacity(), crate::CLASSES[0]);
        let p = b.as_ptr();
        crate::put(b);
        let again = into_bytes(&*String::from("x"));
        assert_eq!(again.as_ptr(), p, "the buffer was reused");
        assert_eq!(again, b"x");
        assert!(into_bytes("").is_empty() && into_bytes("").capacity() == 0);
    }

    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)] // `&String` is the case under test
    fn other_types_convert_as_before() {
        let s = String::with_capacity(100) + "owned";
        let p = s.as_ptr();
        let b = into_bytes(s);
        assert_eq!(
            (b.as_ptr(), &b[..]),
            (p, &b"owned"[..]),
            "a String is moved, not copied"
        );
        assert_eq!(into_bytes('c'), b"c");
        assert_eq!(into_bytes(&String::from("ref")), b"ref");
        assert_eq!(into_bytes(Box::<str>::from("boxed")), b"boxed");
        assert_eq!(into_bytes(std::borrow::Cow::Borrowed("cow")), b"cow");
    }
}
