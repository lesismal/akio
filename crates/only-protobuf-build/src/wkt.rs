//! The well-known types' `.proto` definitions, built in so `import
//! "google/protobuf/timestamp.proto"` works without the files on disk. Their Rust types live in
//! `only_protobuf::well_known`.

pub(crate) const FILES: &[(&str, &str)] = &[
    (
        "google/protobuf/empty.proto",
        r#"syntax = "proto3";
package google.protobuf;

// A generic empty message, for methods that take or return nothing.
message Empty {}
"#,
    ),
    (
        "google/protobuf/timestamp.proto",
        r#"syntax = "proto3";
package google.protobuf;

// A point in time independent of any time zone: seconds and nanoseconds since the Unix epoch
// (1970-01-01T00:00:00Z), UTC, with leap seconds smeared.
message Timestamp {
  // Seconds since the epoch; 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z.
  int64 seconds = 1;
  // Non-negative fractions of a second at nanosecond resolution, 0 to 999,999,999.
  int32 nanos = 2;
}
"#,
    ),
    (
        "google/protobuf/duration.proto",
        r#"syntax = "proto3";
package google.protobuf;

// A signed span of time: seconds and nanoseconds (both with the same sign).
message Duration {
  // Seconds, -315,576,000,000 to +315,576,000,000 (about 10,000 years).
  int64 seconds = 1;
  // Fractions of a second at nanosecond resolution, -999,999,999 to +999,999,999, with the
  // sign of `seconds`.
  int32 nanos = 2;
}
"#,
    ),
    (
        "google/protobuf/any.proto",
        r#"syntax = "proto3";
package google.protobuf;

// An arbitrary message with a URL naming its type.
message Any {
  // `type.googleapis.com/<full message name>`.
  string type_url = 1;
  // The encoded message.
  bytes value = 2;
}
"#,
    ),
    (
        "google/protobuf/wrappers.proto",
        r#"syntax = "proto3";
package google.protobuf;

// Wrapper message for `double`.
message DoubleValue {
  // The value.
  double value = 1;
}
// Wrapper message for `float`.
message FloatValue {
  // The value.
  float value = 1;
}
// Wrapper message for `int64`.
message Int64Value {
  // The value.
  int64 value = 1;
}
// Wrapper message for `uint64`.
message UInt64Value {
  // The value.
  uint64 value = 1;
}
// Wrapper message for `int32`.
message Int32Value {
  // The value.
  int32 value = 1;
}
// Wrapper message for `uint32`.
message UInt32Value {
  // The value.
  uint32 value = 1;
}
// Wrapper message for `bool`.
message BoolValue {
  // The value.
  bool value = 1;
}
// Wrapper message for `string`.
message StringValue {
  // The value.
  string value = 1;
}
// Wrapper message for `bytes`.
message BytesValue {
  // The value.
  bytes value = 1;
}
"#,
    ),
    (
        "google/protobuf/field_mask.proto",
        r#"syntax = "proto3";
package google.protobuf;

// A set of symbolic field paths, such as `user.display_name`.
message FieldMask {
  // The paths.
  repeated string paths = 1;
}
"#,
    ),
    (
        "google/protobuf/struct.proto",
        r#"syntax = "proto3";
package google.protobuf;

// A JSON object: field names to dynamically typed values.
message Struct {
  // The fields.
  map<string, Value> fields = 1;
}

// A dynamically typed JSON value.
message Value {
  // The kind of value.
  oneof kind {
    // JSON `null`.
    NullValue null_value = 1;
    // A JSON number.
    double number_value = 2;
    // A JSON string.
    string string_value = 3;
    // A JSON boolean.
    bool bool_value = 4;
    // A JSON object.
    Struct struct_value = 5;
    // A JSON array.
    ListValue list_value = 6;
  }
}

// The JSON `null` value.
enum NullValue {
  // Null.
  NULL_VALUE = 0;
}

// A JSON array.
message ListValue {
  // The values.
  repeated Value values = 1;
}
"#,
    ),
];

/// The built-in source of `name`, if it is a well-known type file.
pub(crate) fn source(name: &str) -> Option<&'static str> {
    FILES.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}
