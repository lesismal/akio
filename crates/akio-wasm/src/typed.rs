//! Typed functions: Rust's types for WebAssembly's, so that host functions and calls into the
//! guest take and return plain values, their WebAssembly type checked once.

use std::{fmt, marker::PhantomData};

use crate::{
    budget::Budget,
    store::{Caller, Store},
    trap::Trap,
    types::{FuncType, ValType},
    value::{Func, Value},
};

mod sealed {
    pub trait Sealed {}
}

/// A Rust type that stands for a WebAssembly value type: `i32` and `u32` for `i32`, `i64` and
/// `u64` for `i64` (the unsigned ones as their two's complement), `f32` and `f64`.
pub trait WasmTy: sealed::Sealed + Copy + Send + 'static {
    /// The WebAssembly type.
    const TY: ValType;
    #[doc(hidden)]
    fn from_value(v: Value) -> Option<Self>;
    #[doc(hidden)]
    fn into_value(self) -> Value;
    /// From a slot's bits (an `i32` zero-extended, a float's bits).
    #[doc(hidden)]
    fn from_slot(v: u64) -> Self;
    #[doc(hidden)]
    fn into_slot(self) -> u64;
}

macro_rules! wasm_ty {
    (
        $t:ty, $vt:ident, $v:ident, |$x:ident| $from:expr, |$y:ident| $into:expr,
        |$s:ident| $from_slot:expr, |$z:ident| $into_slot:expr
    ) => {
        impl sealed::Sealed for $t {}
        impl WasmTy for $t {
            const TY: ValType = ValType::$vt;
            #[inline]
            fn from_value(v: Value) -> Option<Self> {
                match v {
                    Value::$v($x) => Some($from),
                    _ => None,
                }
            }
            #[inline]
            fn into_value(self) -> Value {
                let $y = self;
                Value::$v($into)
            }
            #[inline(always)]
            fn from_slot($s: u64) -> Self {
                $from_slot
            }
            #[inline(always)]
            fn into_slot(self) -> u64 {
                let $z = self;
                $into_slot
            }
        }
    };
}

wasm_ty!(i32, I32, I32, |x| x, |y| y, |s| s as u32 as i32, |z| {
    u64::from(z as u32)
});
wasm_ty!(
    u32,
    I32,
    I32,
    |x| x as u32,
    |y| y as i32,
    |s| s as u32,
    |z| u64::from(z)
);
wasm_ty!(i64, I64, I64, |x| x, |y| y, |s| s as i64, |z| z as u64);
wasm_ty!(u64, I64, I64, |x| x as u64, |y| y as i64, |s| s, |z| z);
wasm_ty!(
    f32,
    F32,
    F32,
    |x| x,
    |y| y,
    |s| f32::from_bits(s as u32),
    |z| u64::from(z.to_bits())
);
wasm_ty!(f64, F64, F64, |x| x, |y| y, |s| f64::from_bits(s), |z| z
    .to_bits());

/// A function's parameters: a Rust tuple of [`WasmTy`]s, `()`, `(i32,)`, `(i32, u64)` ... up to
/// twelve, or a single one.
pub trait WasmParams: sealed::Sealed + Sized + Send + 'static {
    /// How many.
    const N: usize;
    #[doc(hidden)]
    fn push_types(out: &mut Vec<ValType>);
    #[doc(hidden)]
    fn from_values(v: &[Value]) -> Option<Self>;
    #[doc(hidden)]
    fn write_values(self, out: &mut [Value]);
    /// From `N` slots of the right types (a typed host function's arguments).
    #[doc(hidden)]
    fn from_slots(v: &[u64]) -> Self;
}

/// A function's results, as [`WasmParams`]: `()` for none, a tuple, or a single [`WasmTy`].
pub trait WasmResults: Sized + Send + 'static {
    /// How many.
    const N: usize;
    #[doc(hidden)]
    fn push_types(out: &mut Vec<ValType>);
    #[doc(hidden)]
    fn from_values(v: &[Value]) -> Option<Self>;
    #[doc(hidden)]
    fn write_values(self, out: &mut [Value]);
    /// Writes the `N` results to slots (a typed host function's results).
    ///
    /// # Errors
    ///
    /// [`Trap::Host`] for a result that is not of the type `push_types` says.
    #[doc(hidden)]
    fn write_slots(self, out: &mut [u64]) -> Result<(), Trap> {
        let mut types = Vec::with_capacity(Self::N);
        Self::push_types(&mut types);
        let mut values = vec![Value::I32(0); Self::N];
        self.write_values(&mut values);
        for ((o, v), t) in out.iter_mut().zip(values).zip(types) {
            *o = match v {
                Value::I32(x) if t == ValType::I32 => u64::from(x as u32),
                Value::I64(x) if t == ValType::I64 => x as u64,
                Value::F32(x) if t == ValType::F32 => u64::from(x.to_bits()),
                Value::F64(x) if t == ValType::F64 => x.to_bits(),
                _ => {
                    return Err(Trap::Host(
                        "a host function's result of the wrong type".into(),
                    ));
                }
            };
        }
        Ok(())
    }
}

impl<T: WasmTy> WasmParams for T {
    const N: usize = 1;
    fn push_types(out: &mut Vec<ValType>) {
        out.push(T::TY);
    }
    fn from_values(v: &[Value]) -> Option<Self> {
        match v {
            [x] => T::from_value(*x),
            _ => None,
        }
    }
    fn write_values(self, out: &mut [Value]) {
        out[0] = self.into_value();
    }
    #[inline(always)]
    fn from_slots(v: &[u64]) -> Self {
        T::from_slot(v[0])
    }
}

impl<T: WasmTy> WasmResults for T {
    const N: usize = 1;
    fn push_types(out: &mut Vec<ValType>) {
        out.push(T::TY);
    }
    fn from_values(v: &[Value]) -> Option<Self> {
        match v {
            [x] => T::from_value(*x),
            _ => None,
        }
    }
    fn write_values(self, out: &mut [Value]) {
        out[0] = self.into_value();
    }
    #[inline(always)]
    fn write_slots(self, out: &mut [u64]) -> Result<(), Trap> {
        out[0] = self.into_slot();
        Ok(())
    }
}

macro_rules! count {
    () => { 0 };
    ($h:ident $($t:ident)*) => { 1 + count!($($t)*) };
}

macro_rules! tuples {
    ($($n:ident)*) => {
        impl<$($n: WasmTy),*> sealed::Sealed for ($($n,)*) {}

        impl<$($n: WasmTy),*> WasmParams for ($($n,)*) {
            const N: usize = count!($($n)*);
            fn push_types(_out: &mut Vec<ValType>) {
                $(_out.push($n::TY);)*
            }
            #[allow(non_snake_case, unused_mut, unused_variables)]
            fn from_values(v: &[Value]) -> Option<Self> {
                if v.len() != <Self as WasmParams>::N {
                    return None;
                }
                let mut it = v.iter();
                $(let $n = $n::from_value(*it.next()?)?;)*
                Some(($($n,)*))
            }
            #[allow(non_snake_case, unused_mut, unused_variables)]
            fn write_values(self, out: &mut [Value]) {
                let ($($n,)*) = self;
                let mut it = out.iter_mut();
                $(if let Some(o) = it.next() { *o = $n.into_value(); })*
            }
            #[allow(non_snake_case, unused_mut, unused_variables, clippy::unused_unit)]
            #[inline(always)]
            fn from_slots(v: &[u64]) -> Self {
                let mut it = v.iter();
                ($($n::from_slot(it.next().copied().unwrap_or(0)),)*)
            }
        }

        impl<$($n: WasmTy),*> WasmResults for ($($n,)*) {
            const N: usize = <Self as WasmParams>::N;
            fn push_types(out: &mut Vec<ValType>) {
                <Self as WasmParams>::push_types(out);
            }
            fn from_values(v: &[Value]) -> Option<Self> {
                <Self as WasmParams>::from_values(v)
            }
            fn write_values(self, out: &mut [Value]) {
                <Self as WasmParams>::write_values(self, out);
            }
            #[allow(non_snake_case, unused_mut, unused_variables)]
            #[inline(always)]
            fn write_slots(self, out: &mut [u64]) -> Result<(), Trap> {
                let ($($n,)*) = self;
                let mut it = out.iter_mut();
                $(if let Some(o) = it.next() { *o = $n.into_slot(); })*
                Ok(())
            }
        }
    };
}

tuples!();
tuples!(A);
tuples!(A B);
tuples!(A B C);
tuples!(A B C D);
tuples!(A B C D E);
tuples!(A B C D E F);
tuples!(A B C D E F G);
tuples!(A B C D E F G H);
tuples!(A B C D E F G H I);
tuples!(A B C D E F G H I J);
tuples!(A B C D E F G H I J K);
tuples!(A B C D E F G H I J K L);

/// The function type of `P` to `R`.
pub(crate) fn func_type<P: WasmParams, R: WasmResults>() -> FuncType {
    let mut params = Vec::with_capacity(P::N);
    P::push_types(&mut params);
    let mut results = Vec::with_capacity(R::N);
    R::push_types(&mut results);
    FuncType::new(&params, &results)
}

/// The most values a typed call passes in one go without allocating.
const INLINE: usize = 12;

/// A function of the store whose type was checked once against `P` and `R`, called with Rust
/// values ([`Store::typed_func`]).
///
/// ```
/// # use std::sync::Arc;
/// # use akio_wasm::{Budget, InstanceLimits, Module, ModuleLimits, Store};
/// # let bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02,
/// #     0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd',
/// #     0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b];
/// # let module = Arc::new(Module::new(&bytes, &ModuleLimits::default()).unwrap());
/// let mut store = Store::new((), InstanceLimits::default());
/// let inst = store.instantiate(&module, &[], &Budget::unlimited()).unwrap();
/// let f = store.export_func(inst, "add").unwrap();
/// let add = store.typed_func::<(i32, i32), i32>(f).unwrap();
/// assert_eq!(add.call(&mut store, (2, 40), &Budget::fuel(100)), Ok(42));
/// // The wrong type is refused once, here, not at each call.
/// assert!(store.typed_func::<(i64, i64), i64>(f).is_err());
/// ```
pub struct TypedFunc<P, R> {
    func: Func,
    _types: PhantomData<fn(P) -> R>,
}

impl<P, R> Clone for TypedFunc<P, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P, R> Copy for TypedFunc<P, R> {}

impl<P, R> fmt::Debug for TypedFunc<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TypedFunc").field(&self.func).finish()
    }
}

impl<P: WasmParams, R: WasmResults> TypedFunc<P, R> {
    /// The function.
    #[must_use]
    pub const fn func(&self) -> Func {
        self.func
    }

    /// Calls it, as [`Store::call`].
    ///
    /// # Errors
    ///
    /// As [`Store::call`].
    pub fn call<S>(&self, store: &mut Store<S>, params: P, budget: &Budget) -> Result<R, Trap> {
        self.with_values(params, |args, results| {
            store.call(self.func, args, results, budget)
        })
    }

    /// Calls it from a host function, under the same call's budget, as [`Caller::call`].
    ///
    /// # Errors
    ///
    /// As [`Caller::call`].
    pub fn call_from<S>(&self, caller: &mut Caller<'_, S>, params: P) -> Result<R, Trap> {
        self.with_values(params, |args, results| {
            caller.call(self.func, args, results)
        })
    }

    fn with_values(
        &self,
        params: P,
        call: impl FnOnce(&[Value], &mut [Value]) -> Result<(), Trap>,
    ) -> Result<R, Trap> {
        let mut args = [Value::I32(0); INLINE];
        let mut results = [Value::I32(0); INLINE];
        params.write_values(&mut args[..P::N]);
        call(&args[..P::N], &mut results[..R::N])?;
        R::from_values(&results[..R::N]).ok_or(Trap::BadCall("results of the wrong type"))
    }
}

impl<S> Store<S> {
    /// `f` as a [`TypedFunc`] of parameters `P` and results `R`, its type checked now.
    ///
    /// # Errors
    ///
    /// [`Trap::BadCall`] if `f`'s type is not `P` to `R`.
    ///
    /// # Panics
    ///
    /// If `f` belongs to another store.
    pub fn typed_func<P: WasmParams, R: WasmResults>(
        &self,
        f: Func,
    ) -> Result<TypedFunc<P, R>, Trap> {
        if *self.func_type(f) != func_type::<P, R>() {
            return Err(Trap::BadCall(
                "the function's type is not the one asked for",
            ));
        }
        Ok(TypedFunc {
            func: f,
            _types: PhantomData,
        })
    }
}
