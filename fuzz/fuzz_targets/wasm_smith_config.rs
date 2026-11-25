// The `wasm-smith` configuration of the akio-wasm targets (`wasm_exec`, `wasm_diff`), included
// by both with `#[path]`.

use libfuzzer_sys::arbitrary::{Result, Unstructured};

/// What `akio-wasm` implements: WebAssembly 2.0 without SIMD, one memory.
pub fn config(u: &mut Unstructured<'_>) -> Result<wasm_smith::Config> {
    let mut c: wasm_smith::Config = u.arbitrary()?;
    c.simd_enabled = false;
    c.relaxed_simd_enabled = false;
    c.threads_enabled = false;
    c.shared_everything_threads_enabled = false;
    c.exceptions_enabled = false;
    c.gc_enabled = false;
    c.tail_call_enabled = false;
    c.memory64_enabled = false;
    c.extended_const_enabled = false;
    c.wide_arithmetic_enabled = false;
    c.custom_page_sizes_enabled = false;
    c.custom_descriptors_enabled = false;
    c.compact_imports_enabled = false;
    c.multibyte_array_access_enabled = false;
    c.acquire_release_atomics_enabled = false;
    c.max_memories = c.max_memories.min(1);
    c.max_tables = c.max_tables.min(4);
    c.max_memory32_bytes = c.max_memory32_bytes.min(1 << 20);
    c.max_table_elements = c.max_table_elements.min(1000);
    c.max_funcs = c.max_funcs.min(30);
    c.max_instructions = c.max_instructions.min(500);
    c.export_everything = true;
    Ok(c)
}
