//! Limits on loading a module (ADR-125, section 3).

/// Bounds checked while a module is decoded, before anything is allocated for what they count,
/// so that loading stays linear in the module's size and a hostile module is refused early.
///
/// The defaults are generous for real guests: fit's Go plugins (2–5 MB, 1 700–2 600 functions)
/// are far inside every one. Build from [`ModuleLimits::default`] and change fields:
///
/// ```
/// let mut limits = akio_wasm::ModuleLimits::default();
/// limits.max_module_bytes = 8 << 20;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ModuleLimits {
    /// The module's size in bytes (64 MiB).
    pub max_module_bytes: usize,
    /// Function types in the type section (100 000).
    pub max_types: u32,
    /// Parameters, and separately results, of one function type (1 000).
    pub max_type_arity: u32,
    /// Functions, imported and defined (100 000).
    pub max_funcs: u32,
    /// Imports (10 000).
    pub max_imports: u32,
    /// Exports (10 000).
    pub max_exports: u32,
    /// Tables, imported and defined (100).
    pub max_tables: u32,
    /// A table's initial size, in elements (10 M); its growth is an instance's limit.
    pub max_table_elements: u32,
    /// Globals, imported and defined (100 000).
    pub max_globals: u32,
    /// Locals of one function, its parameters included (50 000).
    pub max_locals: u32,
    /// Nested blocks, loops and ifs in one function, its own body included (1 000).
    pub max_nesting: u32,
    /// Targets of one `br_table`, its default included (100 000).
    pub max_br_table_targets: u32,
    /// Element segments (100 000).
    pub max_elem_segments: u32,
    /// Data segments (100 000).
    pub max_data_segments: u32,
}

impl Default for ModuleLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: 64 << 20,
            max_types: 100_000,
            max_type_arity: 1_000,
            max_funcs: 100_000,
            max_imports: 10_000,
            max_exports: 10_000,
            max_tables: 100,
            max_table_elements: 10_000_000,
            max_globals: 100_000,
            max_locals: 50_000,
            max_nesting: 1_000,
            max_br_table_targets: 100_000,
            max_elem_segments: 100_000,
            max_data_segments: 100_000,
        }
    }
}
