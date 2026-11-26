//! The linker: host functions by module and name, resolved when an instance is made.

use std::{collections::HashMap, fmt, sync::Arc};

use crate::{
    budget::Budget,
    module::Module,
    store::{Caller, HostFn, InstantiateError, Store},
    trap::Trap,
    typed::{WasmParams, WasmResults, func_type},
    types::{ExternType, FuncType},
    value::{Extern, Instance, Value},
};

/// Why [`Linker`] refused a definition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkError {
    /// `module`.`name` is defined already.
    Duplicate {
        /// The module name.
        module: Box<str>,
        /// The name.
        name: Box<str>,
    },
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { module, name } => write!(f, "{module}.{name} is defined already"),
        }
    }
}

impl std::error::Error for LinkError {}

struct Def<S> {
    ty: FuncType,
    f: HostFn<S>,
}

impl<S> Clone for Def<S> {
    fn clone(&self) -> Self {
        Self {
            ty: self.ty.clone(),
            f: self.f.clone(),
        }
    }
}

/// Host functions by module and name, and how to resolve a module's imports with them
/// (ADR-125, section 3).
///
/// A linker belongs to no store: it is defined once, then instantiates modules into any number
/// of stores ([`Linker::instantiate`]), each import resolved by its module and name, and its
/// type checked against the definition. It is `Clone`, and `Send` and `Sync`, to be shared by
/// the threads of a pool.
///
/// ```
/// use std::sync::Arc;
/// use akio_wasm::{Budget, Caller, InstanceLimits, Linker, Module, ModuleLimits, Store, Trap};
///
/// // (module (import "host" "double" (func $d (param i32) (result i32)))
/// //   (func (export "run") (param i32) (result i32) local.get 0 call $d))
/// let bytes = [
///     0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01,
///     0x7f, 0x02, 0x0f, 0x01, 0x04, b'h', b'o', b's', b't', 0x06, b'd', b'o', b'u', b'b', b'l',
///     b'e', 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, b'r', b'u', b'n', 0x00,
///     0x01, 0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0x10, 0x00, 0x0b,
/// ];
/// let module = Arc::new(Module::new(&bytes, &ModuleLimits::default()).unwrap());
///
/// // The host's state counts the calls.
/// let mut linker = Linker::<u32>::new();
/// linker
///     .func_wrap("host", "double", |c: &mut Caller<'_, u32>, (x,): (i32,)| {
///         *c.state_mut() += 1;
///         x.checked_mul(2).ok_or_else(|| Trap::Host("overflow".into()))
///     })
///     .unwrap();
///
/// let mut store = Store::new(0, InstanceLimits::default());
/// let inst = linker.instantiate(&mut store, &module, &Budget::unlimited()).unwrap();
/// let run = store.typed_func::<i32, i32>(store.export_func(inst, "run").unwrap()).unwrap();
/// assert_eq!(run.call(&mut store, 21, &Budget::fuel(1000)), Ok(42));
/// assert_eq!(*store.state(), 1);
/// ```
pub struct Linker<S> {
    defs: HashMap<(Box<str>, Box<str>), Def<S>>,
    trap_unresolved: bool,
}

impl<S> Clone for Linker<S> {
    fn clone(&self) -> Self {
        Self {
            defs: self.defs.clone(),
            trap_unresolved: self.trap_unresolved,
        }
    }
}

impl<S> Default for Linker<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> fmt::Debug for Linker<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Linker")
            .field("funcs", &self.defs.len())
            .field("trap_unresolved", &self.trap_unresolved)
            .finish()
    }
}

impl<S> Linker<S> {
    /// An empty linker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            defs: HashMap::new(),
            trap_unresolved: false,
        }
    }

    /// Defines `module`.`name`, a host function of type `ty` taking its arguments and filling
    /// its results as [`Value`]s, as [`Store::func_new`] (each result already holds its type's
    /// zero).
    ///
    /// # Errors
    ///
    /// [`LinkError::Duplicate`] if `module`.`name` is defined already.
    pub fn func_new(
        &mut self,
        module: &str,
        name: &str,
        ty: FuncType,
        f: impl Fn(&mut Caller<'_, S>, &[Value], &mut [Value]) -> Result<(), Trap>
        + Send
        + Sync
        + 'static,
    ) -> Result<&mut Self, LinkError> {
        self.define(module, name, ty, HostFn::Values(Arc::new(f)))
    }

    /// Defines `module`.`name`, a typed host function: its type is `P` to `R` (a tuple of
    /// [`WasmTy`](crate::WasmTy)s to `()`, one of them or a tuple), and it takes and returns
    /// Rust values.
    ///
    /// # Errors
    ///
    /// [`LinkError::Duplicate`] if `module`.`name` is defined already.
    pub fn func_wrap<P: WasmParams, R: WasmResults>(
        &mut self,
        module: &str,
        name: &str,
        f: impl Fn(&mut Caller<'_, S>, P) -> Result<R, Trap> + Send + Sync + 'static,
    ) -> Result<&mut Self, LinkError> {
        let ty = func_type::<P, R>();
        self.define(
            module,
            name,
            ty,
            // Over slots: the types were checked when the guest's import was linked.
            HostFn::Slots(Arc::new(move |c: &mut Caller<'_, S>, slots: &mut [u64]| {
                let p = P::from_slots(&slots[..P::N]);
                f(c, p)?.write_slots(&mut slots[..R::N])
            })),
        )
    }

    pub(crate) fn define(
        &mut self,
        module: &str,
        name: &str,
        ty: FuncType,
        f: HostFn<S>,
    ) -> Result<&mut Self, LinkError> {
        let key = (Box::from(module), Box::from(name));
        if self.defs.contains_key(&key) {
            return Err(LinkError::Duplicate {
                module: key.0,
                name: key.1,
            });
        }
        self.defs.insert(key, Def { ty, f });
        Ok(self)
    }

    /// Whether a function import nothing defines makes the module unlinkable (by default) or
    /// resolves to a function that traps when called, with [`Trap::Host`] naming it. A module may
    /// import functions it never calls (fit's Go guests import all of fit's modules); with this
    /// on, it loads, and fails only if it calls one. Imports of tables, memories and globals
    /// must always be defined.
    pub fn trap_unresolved(&mut self, on: bool) -> &mut Self {
        self.trap_unresolved = on;
        self
    }

    /// The type of `module`.`name`, if it is defined.
    #[must_use]
    pub fn func_type(&self, module: &str, name: &str) -> Option<&FuncType> {
        self.defs
            .get(&(Box::from(module), Box::from(name)))
            .map(|d| &d.ty)
    }

    /// Instantiates `module` in `store`, its imports resolved by this linker, as
    /// [`Store::instantiate`]: the active segments are written and the start function, if any,
    /// runs under `budget`. A WASI reactor's `_initialize` is the caller's to run next
    /// ([`Store::initialize_reactor`]).
    ///
    /// Each function import becomes a host function of the store, one per import.
    ///
    /// # Errors
    ///
    /// [`InstantiateError::UnknownImport`] for an import nothing defines (unless it is a
    /// function and [`trap_unresolved`](Self::trap_unresolved) is on),
    /// [`InstantiateError::Unlinkable`] for one defined with another type, then as
    /// [`Store::instantiate`].
    pub fn instantiate(
        &self,
        store: &mut Store<S>,
        module: &Arc<Module>,
        budget: &Budget,
    ) -> Result<Instance, InstantiateError> {
        if store.ended() {
            return Err(InstantiateError::Trap(Trap::Ended));
        }
        let mut imports = Vec::with_capacity(module.imports().len());
        for (index, imp) in module.imports().iter().enumerate() {
            let unknown = || InstantiateError::UnknownImport {
                index,
                module: imp.module.clone(),
                name: imp.name.clone(),
            };
            let ExternType::Func(want) = &imp.ty else {
                return Err(unknown());
            };
            let key = (imp.module.clone(), imp.name.clone());
            let f = match self.defs.get(&key) {
                Some(d) if d.ty == *want => store.func_arc(&d.ty, d.f.clone()),
                Some(_) => {
                    return Err(InstantiateError::Unlinkable {
                        index,
                        message: "incompatible import type",
                    });
                }
                None if self.trap_unresolved => {
                    let msg: Box<str> =
                        format!("called unresolved import {}.{}", imp.module, imp.name).into();
                    store.func_arc(
                        want,
                        HostFn::Values(Arc::new(
                            move |_: &mut Caller<'_, S>, _: &[Value], _: &mut [Value]| {
                                Err(Trap::Host(msg.clone()))
                            },
                        )),
                    )
                }
                None => return Err(unknown()),
            };
            imports.push(Extern::Func(f));
        }
        store.instantiate(module, &imports, budget)
    }
}
