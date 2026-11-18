# ADR-030: protobuf text format

English | [简体中文](030-protobuf-text-format.zh-CN.md)

Status: accepted (2026-11-18)

## Context

ADR-022 gave `only-protobuf` runtime reflection (`DescriptorPool`, `DynamicMessage`) and the
canonical JSON mapping, and left the text format out: the protobuf conformance runner skipped its
909 text-format cases. The text format is what protoc's `--decode`, `DebugString`, test fixtures,
configuration files (`.textproto`, `.pbtxt`) and many tools read and write.

## Decision

A new module, `only_protobuf::text`, on top of reflection, mirroring `only_protobuf::json`. All
additive; generated code is unchanged.

- `to_string`, `to_string_with(&PrintOptions)`, `from_str`, `from_str_with(&ParseOptions)` for
  generated messages (`ReflectMessage`); `parse_dynamic`, `DynamicMessage::to_text` /
  `from_text` for dynamic ones. `TextError` carries the line and column (from 1).
- `PrintOptions { single_line, print_unknown_fields, type_pool }`;
  `ParseOptions { allow_unknown_fields, type_pool }`; `RECURSION_LIMIT` (100).
- Parsing follows the [text format spec](https://protobuf.dev/reference/protobuf/textformat-spec/):
  - scalars; enums by name or number (a closed enum takes only its declared numbers);
  - strings and bytes with every escape (simple, octal, `\x`, `\u`, `\U`; surrogates and code
    points above U+10FFFF rejected), adjacent literals joined, UTF-8 required for strings;
  - messages in `{ }` or `< >` with an optional `:`; repeated fields one value at a time or as
    `[a, b]`; maps as entry messages (the last value of a repeated key wins);
  - oneofs; groups by their type name or field name; extensions as `[pkg.ext]` (MessageSet items
    also by their type name); `Any` expanded as `[prefix/pkg.Type] { ... }`, with whitespace and
    comments allowed inside the brackets as protoc does;
  - `#` comments, `,` or `;` after a field;
  - integers in decimal, octal and hex, range-checked; floats with an optional `f` suffix,
    `inf` / `infinity` / `nan` in any case, out-of-range values to infinity or (signed) zero,
    hex and octal rejected for floats.
- Like protoc's `TextFormat::Parse`: a singular field or a second member of a oneof given twice
  is an error, fields named in `reserved` are skipped, unknown fields and extensions are errors
  unless `allow_unknown_fields`.
- Printing matches protoc's printer: fields in number order with extensions among them, two-space
  indentation (or one line), repeated fields one value per line, map entries by key with both
  `key` and `value`, groups by type name, enums by name, floats as the shortest text that reads
  back the same (`inf`, `-inf`, `nan`), strings with C escapes (bytes as octal, UTF-8 kept in
  strings), `Any` expanded when its type is in the pool (or `type_pool`).
- Divergences from protoc: an `Any` is printed raw (not expanded) when its type URL would not read
  back the same, or when its value has unknown fields and they are not printed, so printing loses
  nothing; an octal escape above `\377` is an error; a singular proto3 field given twice is an
  error even when its first value was the default (protoc checks `HasField`). Not supported:
  parsing fields by number (`AllowFieldNumber`), protoc's opt-in merge mode
  (`TextFormat::Merge`, which lets a singular field be given twice).

## Verification

- Protobuf conformance runner v35.1 (`tools/protobuf-test/conformance/run.sh`,
  `--enforce_recommended --maximum_edition 2024`): text format 909 passed, 0 failed, 0 skipped
  (proto2, proto3, editions); binary + JSON unchanged at 5627 passed.
- `tools/protobuf-test/tests/text.rs` (exact output, every input form, errors, groups,
  extensions, MessageSet, `Any`, unknown fields, floats, a mutation smoke test) and unit tests in
  the module.
- Fuzz target `protobuf_text`: text parse → print → parse (multi-line and single-line) must print
  the same text and the same encoded length; binary input must print with unknown fields and
  read back.

## Consequences

The text format adds code to the crate but none to encoding and decoding or to generated code.
It works on any message with descriptors (the default); `Config::descriptors(false)` messages
can use it only through a `DescriptorPool` built some other way.
