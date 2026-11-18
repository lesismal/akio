# ADR-022: protobuf groups, extensions, editions, JSON and reflection

English | [简体中文](022-protobuf-gaps.zh-CN.md)

Status: accepted (2026-11-18)

## Context

`only-protobuf` / `only-protobuf-build` (ADR-005: no third-party dependencies, no `protoc`)
covered proto2 and proto3 messages, enums, maps, oneofs and the common well-known types. Not
done (DEV-PLAN): proto2 groups and extensions, editions, the canonical JSON mapping, and runtime
reflection, without which gRPC server reflection (grpcurl, grpcui) cannot work.

## Decision

All additive; generated code still names only `::only_protobuf` (and `::only_grpc` for stubs).

**Groups and extensions.**
- `encoding::GroupCodec<M, const N: u32>` encodes a message as a group of field `N`; generated
  code uses it for proto2 `group` fields and for `features.message_encoding = DELIMITED`.
- `ExtensionSet` keeps a message's extension fields in their encoded form (by field number,
  written back interleaved with the declared fields in number order, as protoc does). Messages
  with extension ranges get `pub extensions: ExtensionSet` (also with `Config::unknown_fields(false)`)
  and implement `Extendable`. Each `extend` field becomes a typed constant
  (`Extension<Extendee, Codec>` / `RepeatedExtension`), read and written with
  `msg.extension(&EXT)`, `set_extension`, `has_extension`, `clear_extension`,
  `repeated_extension`, `set_repeated_extension`. Extension payloads are decoded when read
  (an error inside one surfaces then, not at message decode).
- MessageSet (`message_set_wire_format`) items map to extensions.
- **Closed enums** (proto2 enums, `features.enum_type = CLOSED`): an unknown number is kept in
  the unknown fields instead of the field (C++ and Go behaviour; a map entry with an unknown value
  goes there whole). `Enumeration::is_known` is new (provided method). This changes decoding of
  proto2 enum fields with unknown numbers.

**Editions 2023 and 2024.** `edition = "2023" | "2024"` files are parsed, `features.*` options
resolved per file / message / field / enum (field presence including `LEGACY_REQUIRED`, enum
openness, packed or expanded, delimited, UTF-8, JSON format; 2024 naming style checks and
`export` / `local` symbol visibility, `import option`). proto2 / proto3 files map to the
equivalent legacy features, so one resolver drives both. Divergence: `utf8_validation = NONE`
string fields are still `String` and still checked (Rust strings are UTF-8, as with prost); the
feature is recorded in the descriptors.

**Descriptors.** The generator builds `FileDescriptorProto`s as protoc writes them (map entry
types, synthetic oneofs, JSON names, canonical defaults, options, custom options and text-format
aggregates encoded against `descriptor.proto`, source-retention options dropped), now built in
with `type.proto`, `api.proto` and `source_context.proto`. Each generated package has
`FILE_DESCRIPTOR_SET` (its files and their imports) and `descriptor_pool()`.
`Config::descriptors(bool)` (default on) and `Config::file_descriptor_set_path`.

**Reflection** (`only_protobuf::reflect`): `DescriptorPool` (from encoded sets, validated,
names resolved, features resolved), `FileDescriptor`, `MessageDescriptor`, `FieldDescriptor`,
`EnumDescriptor`, `ServiceDescriptor`, `MethodDescriptor`; `DynamicMessage` / `Value` /
`MapKey` (decode, encode, get, set, oneofs, extensions, unknown fields); `ReflectMessage`
(generated: `descriptor()`, `to_dynamic`, `from_dynamic`).

**JSON** (`only_protobuf::json`): the proto3 JSON mapping on top of reflection: `to_string`,
`to_string_with(&PrintOptions)`, `from_str`, `from_str_with(&ParseOptions)` (with
`ignore_unknown_fields`), `parse_dynamic`, `DynamicMessage::to_json` / `from_json`; well-known
types, `json_name`, extensions as `[full.name]`, own strict JSON parser.

**gRPC server reflection** (`only_grpc::reflection`): `register(server, &pool)` adds
`grpc.reflection.v1.ServerReflection` and `v1alpha` (list services, files by name / symbol /
extension, extension numbers); the reflection messages are public (`reflection::v1`, `v1alpha`).
only-grpc now depends on only-protobuf.

## Verification

- protoc 35.1 goldens: encodings (groups, extensions, MessageSet, editions 2023 and 2024) decode
  and re-encode byte for byte; descriptor sets equal protoc's `--descriptor_set_out` for 11 files
  (custom options, `descriptor.proto` itself, edition 2024).
- Protobuf conformance runner v35.1 (Docker, `tools/protobuf-test/conformance/run.sh`,
  `--enforce_recommended --maximum_edition 2024`): binary + JSON 5627 passed, 0 failed, 4
  skipped (the UNSTABLE-edition message); text format not implemented (skipped).
- grpcurl (`tools/interop/grpc/grpcurl.sh`): list, describe (proto2 groups and extensions,
  edition 2024), and JSON calls through reflection.
- Differential: prost on groups and closed enums, dynamic messages against generated code;
  fuzz targets `protobuf_diff`, `protobuf_descriptor`, `protobuf_json`.

## Consequences

Generated packages embed their descriptors (a few KB each; `Config::descriptors(false)` to drop).
Encode / decode code paths are unchanged apart from the closed-enum arms of proto2 fields and a
tag-length check; same-run A/B in the CHANGELOG entry. Text format is still not supported.
