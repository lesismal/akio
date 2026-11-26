//! A small module builder, and a store with one instance, for the tests.
#![allow(dead_code)]

use std::sync::Arc;

use akio_wasm::{Budget, Instance, InstanceLimits, Module, ModuleLimits, Store, Trap, Value};

pub(crate) fn leb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub(crate) fn sleb(mut v: i64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0) {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub(crate) fn vec_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    leb(items.len() as u64, &mut out);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

pub(crate) fn name(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    leb(s.len() as u64, &mut out);
    out.extend_from_slice(s.as_bytes());
    out
}

pub(crate) const I32: u8 = 0x7f;
pub(crate) const I64: u8 = 0x7e;

/// Instructions, built up with a few helpers.
#[derive(Default, Clone)]
pub(crate) struct Code(pub(crate) Vec<u8>);

impl Code {
    pub(crate) fn op(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    pub(crate) fn get(self, i: u32) -> Self {
        self.op(&[0x20]).idx(i)
    }
    pub(crate) fn set(self, i: u32) -> Self {
        self.op(&[0x21]).idx(i)
    }
    pub(crate) fn tee(self, i: u32) -> Self {
        self.op(&[0x22]).idx(i)
    }
    pub(crate) fn i32c(mut self, v: i32) -> Self {
        self.0.push(0x41);
        sleb(i64::from(v), &mut self.0);
        self
    }
    pub(crate) fn i64c(mut self, v: i64) -> Self {
        self.0.push(0x42);
        sleb(v, &mut self.0);
        self
    }
    pub(crate) fn idx(mut self, i: u32) -> Self {
        leb(u64::from(i), &mut self.0);
        self
    }
    pub(crate) fn call(self, f: u32) -> Self {
        self.op(&[0x10]).idx(f)
    }
    pub(crate) fn end(self) -> Self {
        self.op(&[0x0b])
    }
}

#[derive(Default)]
pub(crate) struct Builder {
    types: Vec<Vec<u8>>,
    imports: Vec<Vec<u8>>,
    imported_funcs: u32,
    funcs: Vec<u32>,
    tables: Vec<Vec<u8>>,
    memory: Option<Vec<u8>>,
    globals: Vec<Vec<u8>>,
    exports: Vec<Vec<u8>>,
    codes: Vec<Vec<u8>>,
}

impl Builder {
    pub(crate) fn ty(&mut self, params: &[u8], results: &[u8]) -> u32 {
        let mut t = vec![0x60];
        leb(params.len() as u64, &mut t);
        t.extend_from_slice(params);
        leb(results.len() as u64, &mut t);
        t.extend_from_slice(results);
        if let Some(i) = self.types.iter().position(|x| *x == t) {
            return i as u32;
        }
        self.types.push(t);
        (self.types.len() - 1) as u32
    }

    pub(crate) fn import_func(&mut self, module: &str, field: &str, ty: u32) -> u32 {
        let mut i = name(module);
        i.extend(name(field));
        i.push(0);
        leb(u64::from(ty), &mut i);
        self.imports.push(i);
        self.imported_funcs += 1;
        self.imported_funcs - 1
    }

    /// A function with `(count, type)` local groups; its index.
    pub(crate) fn func(&mut self, ty: u32, locals: &[(u32, u8)], code: Code) -> u32 {
        let mut b = vec_of(
            &locals
                .iter()
                .map(|&(n, t)| {
                    let mut g = Vec::new();
                    leb(u64::from(n), &mut g);
                    g.push(t);
                    g
                })
                .collect::<Vec<_>>(),
        );
        b.extend(code.0);
        let mut out = Vec::new();
        leb(b.len() as u64, &mut out);
        out.extend(b);
        self.funcs.push(ty);
        self.codes.push(out);
        self.imported_funcs + self.funcs.len() as u32 - 1
    }

    pub(crate) fn export(&mut self, n: &str, f: u32) {
        let mut e = name(n);
        e.push(0);
        leb(u64::from(f), &mut e);
        self.exports.push(e);
    }

    pub(crate) fn export_memory(&mut self, n: &str) {
        let mut e = name(n);
        e.extend([2, 0]);
        self.exports.push(e);
    }

    pub(crate) fn import_memory(&mut self, module: &str, field: &str, min: u32) {
        let mut i = name(module);
        i.extend(name(field));
        i.extend([2, 0]);
        leb(u64::from(min), &mut i);
        self.imports.push(i);
    }

    pub(crate) fn memory(&mut self, min: u32, max: Option<u32>) {
        let mut m = vec![u8::from(max.is_some())];
        leb(u64::from(min), &mut m);
        if let Some(x) = max {
            leb(u64::from(x), &mut m);
        }
        self.memory = Some(m);
    }

    /// A mutable `i32` global holding `v`; its index.
    pub(crate) fn global_i32(&mut self, v: i32) -> u32 {
        let mut g = vec![I32, 1, 0x41];
        sleb(i64::from(v), &mut g);
        g.push(0x0b);
        self.globals.push(g);
        (self.globals.len() - 1) as u32
    }

    pub(crate) fn export_global(&mut self, n: &str, g: u32) {
        let mut e = name(n);
        e.push(3);
        leb(u64::from(g), &mut e);
        self.exports.push(e);
    }

    pub(crate) fn table(&mut self, min: u32, max: Option<u32>) {
        let mut t = vec![0x70, u8::from(max.is_some())];
        leb(u64::from(min), &mut t);
        if let Some(x) = max {
            leb(u64::from(x), &mut t);
        }
        self.tables.push(t);
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        let mut section = |id: u8, content: Vec<u8>| {
            out.push(id);
            leb(content.len() as u64, &mut out);
            out.extend(content);
        };
        section(1, vec_of(&self.types));
        if !self.imports.is_empty() {
            section(2, vec_of(&self.imports));
        }
        let fs: Vec<Vec<u8>> = self
            .funcs
            .iter()
            .map(|&t| {
                let mut v = Vec::new();
                leb(u64::from(t), &mut v);
                v
            })
            .collect();
        section(3, vec_of(&fs));
        if !self.tables.is_empty() {
            section(4, vec_of(&self.tables));
        }
        if let Some(m) = &self.memory {
            section(5, vec_of(std::slice::from_ref(m)));
        }
        if !self.globals.is_empty() {
            section(6, vec_of(&self.globals));
        }
        section(7, vec_of(&self.exports));
        section(10, vec_of(&self.codes));
        out
    }

    pub(crate) fn load(&self) -> Arc<Module> {
        Arc::new(Module::new(&self.build(), &ModuleLimits::default()).expect("module loads"))
    }
}

/// A store with one instance of a module that imports nothing.
pub(crate) struct Inst {
    pub(crate) s: Store<()>,
    pub(crate) inst: Instance,
}

pub(crate) fn store(m: &Arc<Module>, limits: InstanceLimits) -> Inst {
    let mut s = Store::new((), limits);
    let inst = s
        .instantiate(m, &[], &Budget::unlimited())
        .expect("instantiates");
    Inst { s, inst }
}

impl Inst {
    pub(crate) fn call(
        &mut self,
        f: &str,
        args: &[Value],
        budget: &Budget,
    ) -> Result<Vec<Value>, Trap> {
        let func = self.s.export_func(self.inst, f).expect("export");
        let mut out: Vec<Value> = self
            .s
            .func_type(func)
            .results()
            .iter()
            .map(|&t| Value::default_of(t))
            .collect();
        self.s.call(func, args, &mut out, budget)?;
        Ok(out)
    }
}
