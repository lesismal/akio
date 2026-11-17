#![no_main]
//! Descriptor pools from untrusted bytes (what a reflection client receives): building one from
//! an arbitrary `FileDescriptorSet` must fail cleanly or give a pool whose messages decode and
//! re-encode arbitrary input without panicking, and whose dynamic re-encodings decode back.

use only_protobuf::reflect::{DescriptorPool, DynamicMessage};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // First byte: where the descriptor set ends and the message bytes start.
    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let cut = (usize::from(cut) * rest.len() / 255).min(rest.len());
    let (set, msg) = rest.split_at(cut);
    let Ok(pool) = DescriptorPool::decode(set) else {
        return;
    };
    let _ = pool.encode_file_descriptor_set();
    for m in pool.all_messages().take(16) {
        for f in m.fields() {
            let _ = f.default_value();
            let _ = f.map_entry_fields();
        }
        if let Ok(d) = DynamicMessage::decode(m.clone(), msg) {
            let b = d.encode_to_vec();
            let again = DynamicMessage::decode(m, &b).expect("re-encoding decodes");
            assert_eq!(again.encode_to_vec(), b, "re-encoding is stable");
        }
    }
    for s in pool.services() {
        for m in s.methods() {
            let _ = (m.input(), m.output(), m.path());
        }
    }
});
