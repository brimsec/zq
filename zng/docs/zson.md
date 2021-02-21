# ZSON - ZNG Structured Object-record Notation

> ### DRAFT 12/2/20
> ### Note: This specification is in BETA development.
> We plan to have a final form established by Spring 2021.
>
> ZSON is intended as a literal superset of JSON and NDJSON syntax.
> If there is anything in this document that conflicts with this goal,
> please let us know and we will address it.
>
> Regarding the state of the implementation of the ZSON format in zq:
> * An input reader is not yet implemented,
> * End-of-sequence markers are not yet conveyed in the writer.

* [1. Introduction](#1-introduction)
  + [1.1 Some Examples](#11-some-examples)
* [2. The ZSON Data Model](#2-the-zson-data-model)
  + [2.1 Primitive Types](#21-primitive-types)
  + [2.2 Complex Types](#22-complex-types)
  + [2.3 The Type Type](#23-the-type-type)
  + [2.4 The Null Type](#24-the-null-type)
  + [2.5 Type Definitions](#25-type-definitions)
* [3. The ZSON Format](#3-the-zson-format)
  + [3.1 Identifiers](#31-identifiers)
  + [3.2 Type Decorators](#32-type-decorators)
    - [3.2.1 Type Definitions](#321-type-definitions)
  + [3.3 Primitive Values](#33-primitive-values)
    - [3.3.1 String Escape Rules](#331-string-escape-rules)
  + [3.4 Complex Values](#34-complex-values)
    - [3.4.1 Record Value](#341-record-value)
    - [3.4.2 Array Value](#342-array-value)
    - [3.4.3 Set Value](#343-set-value)
    - [3.4.4 Union Value](#344-union-value)
    - [3.4.5 Enum Value](#345-enum-value)
    - [3.4.6 Map Value](#346-map-value)
    - [3.4.7 Type Value](#347-type-value)
  + [3.5 Type Syntax](#35-type-syntax)
    - [3.5.1 Record Type](#351-record-type)
    - [3.5.2 Array Type](#352-array-type)
    - [3.5.3 Set Type](#353-set-type)
    - [3.5.4 Union Type](#354-union-type)
    - [3.5.5 Enum Type](#355-enum-type)
    - [3.5.6 Map Type](#356-map-type)
    - [3.5.7 Type Type](#357-type-type)
  + [3.6 Null Value](#36-null-value)
* [4. Examples](#4-examples)

## 1. Introduction

ZSON is a data model and serialization format that embodies both
"structured" as well as "semi-structured" data.  It is
semantically a superset of the schema-flexible document model of JSON
and the schema-rigid table model of relational systems.

ZSON has the look and feel of JSON but differs substantially
under the covers as it enjoys:
* a comprehensive, embedded type system with first-class types and definitions,
* well-defined streaming semantics, and
* a semantically-matched, performant binary form called ZNG.

ZSON builds upon the elegant simplicity of JSON with "type decorators".
These decorators appear throughout the value syntax unobstrusively,
in an ergonomic and human-readable syntax, to establish a well-defined
type of every value expressed in a ZSON input.

In addition to the human-readable format described here, the ZSON data model
is realized in an efficient binary format called
[ZNG](spec.md) and a columnar variation
of ZNG called [ZST](../../zst/README.md).
While ZNG and ZST are suited for production workflows and operational systems
where performance matters most,
ZSON is appropriate for human-level inspection of raw data
and for test and debug and for low-performance APIs where ergonomics matters
more than performance.

The ZSON design was inspired by the
[Zeek TSV log format](https://docs.zeek.org/en/stable/examples/logs/)
and [is semantically consistent with it](./zeek-compat.md).
As far as we know, the Zeek log format pioneered the concept of
embedding the schemas of log lines as metadata within the log files themselves
and ZSON modernizes this original approach with a JSON-like syntax and
binary format.

### 1.1 Some Examples

The simplest ZSON text is a single value, perhaps a string like this:
```
"hello, world"
```
There's no need for a type decorator here.  It's explicitly a string.

A structured SQL table might look like this:
```
{ city: "Berkeley", state: "CA", population: 121643 (uint32) } (=city_schema)
{ city: "Broad Cove", state: "ME", population: 806 } (city_schema)
{ city: "Baton Rouge", state: "LA", population: 221599 } (city_schema)
```
This ZSON text depicts three record values.  It defines a type called `city_schema`
based on the first value and decorates the two subsequent values with that type.
The inferred value of the `city_schema` type is a record type depicted as:
```
{ city:string, state:string, population:uint32 }
```
When all the values in a sequence have the same record type, the sequence
can be interpreted as a _table_, where the ZSON record values form the _rows_
and the fields of the records form the _columns_.  In this way, these
three records form a relational table conforming to the schema `city_schema`.

In contrast, a ZSON text representing a semi-structured sequence of log lines
might look like this:
```
{
    info: "Connection Example",
    src: { addr: 10.1.1.2, port: 80 (uint16) } (=socket),
    dst: { addr: 10.0.1.2, port: 20130 } (socket)
} (=conn)
{
    info: "Connection Example 2",
    src: { addr: 10.1.1.8, port: 80 },
    dst: { addr: 10.1.2.88, port: 19801 }
} (conn)
{
    info: "Access List Example",
    nets: [ 10.1.1.0/24, 10.1.2.0/24 ]
} (=access_list)
{ metric: "A", ts: 2020-11-24T08:44:09.586441-08:00, value: 120 }
{ metric: "B", ts: 2020-11-24T08:44:20.726057-08:00, value: 0.86 }
{ metric: "A", ts: 2020-11-24T08:44:32.201458-08:00, value: 126 }
{ metric: "C", ts: 2020-11-24T08:44:43.547506-08:00, value: { x:10, y:101 } }
```
In this case, the first record value defines not just the new record type
called `conn`, but also a second embedded record type called `socket`.
The parenthesized decorators are used where a type is not gleaned from
the value itself:
* `socket` is a record with typed fields `addr` and `port` where `port` is an unsigned 16-bit integer, and
* `conn` is a record with typed fields `info`, `src`, and `dst`.

The next value in the sequence is also a `conn` type but given that this
complex type has been defined previously, there is no need to specify the
type decorators for each nested field since they are all determined by the
top-level record type.

The subsequent value defines a type called `access_list`.  In this case,
the `nets` field is an array of networks and illustrates the helpful range of
primitive types in ZSON.  Note that the syntax here implies
the type of the array, as it is inferred from the type of the elements.

Finally, there are four more values that show ZSON's efficacy for
representing metrics.  Here, there are no type decorators as all of the field
types are implied by their syntax, and hence, the top-level record type is implied.
For instance, the `ts` field is an RFC 3339 date/time string,
unambiguously the primitive type `time`.  Further,
note that the `value` field takes on different types and even a complex record
type on the last line.  In this case, there is a different type top-level
record type implied by each of the three variations of type of the `value` field.

Note that when a record is decorated, the field names may be omitted as
the decorator implies the missing names, e.g.,
```
{
    "Connection Example 2",
    { 10.1.1.8, 80 },
    { 10.1.2.88, 19801 }
} (conn)
```

## 2. The ZSON Data Model

ZSON data is defined as an ordered sequence of one or more typed data values
separated at any point or not at all by an end-of-sequence marker `.`.
Each sequence implies a type context as described below and the `.` marker causes
a new type context to be established for subsequent elements of the sequence.

Each value's type is either a "primitive type", a "complex type", the "type type",
or the "null type".

### 2.1 Primitive Types

Primitive types include signed and unsigned integers, IEEE floating point of
several widths, IEEE decimal,
string, bstring, byte sequence, boolean, IP address, and IP network.

> Note: The `bstring` type is an unusual mixture of a UTF-8 string
> with embedded binary data as in
> [Rust's experimental `bstr` library](https://docs.rs/bstr/0.2.14/bstr/).
> This type is useful in systems that, for instance, pull data off the network
> while expecting a string, but sometimes encounter embedded binary data due to
> bugs, malicious attacks, etc.  It is up to the application to differentiate
> between a `bstring` value that happens to look like a valid UTF-8 string and
> an actual UTF-8 string encoded as a `bstring`.

### 2.2 Complex Types

Complex types are composed of primitive types and/or other complex types
and include
* _record_ - an ordered collection of zero or more named values called fields,
* _array_ - an ordered sequence of zero or more values called elements,
* _set_ - a set of zero or more unique values called elements,
* _union_ - a type representing values whose type is any of a specified collection of two or more types,
* _enum_ - a type representing values taken from a specified collection of one or more uniformly
typed values, which can be either primitive or complex, and
* _map_ - a collection of zero or more key/value pairs where the keys are of a
uniform type called the key type and the values are of a uniform type called
the value type.

### 2.3 The Type Type

ZSON also includes first-class types, where a value can be of type `type`.
The syntax for type values is given below.

### 2.4 The Null Type

The _null_ type is a primitive type representing only a `null` value.  A `null`
value can have any type.

### 2.5 Type Definitions

Type definitions embedded in the data sequence bind a name to a type
so that later values can refer to their type by name instead of explicitly
enumerating the type of every element.  A collection of bindings from name to
type is called a "type context."  As bindings are read from a sequence, they
create the sequence's type context.  The context may be reset at any point in
the sequence, implying that a new binding must be defined from that point on
for each unique use of a type.

A type name is either internal or external.  Internal names are used exclusively
to organize the types in the type context within the data sequence itself and have
no meaning outside of that data.  External names are visible outside of
a data sequence as named types, providing external systems a way to
discover and refer to types by name where the type is defined within the data
sequence.  The binding between an external name and its type must be reestablished
in each type context in which it used.  External names are analogous to the notion
of "logical types" in Parquet and Avro.

Internal type names are represented by integers while external names are
represented by identifiers.  When ZSON data is organized into a sequence
comprised of two or more subsequences where each subsequence has its own
type context, the internal names may be "reused" across type contexts to refer
to different types but external names must have the same type value across
subsequences.  It is a "type mismatch" error if an external name has different
type values across subsequences.

## 3. The ZSON Format

A ZSON text is a sequence of UTF-8 characters organized either as a bounded input
or as or an unbounded stream.  Like NDJSON, ZSON input represents a sequence of
data objects that can be incrementally parsed and is human readable,
though ZSON values must be individually parsed to find their boundaries
as they are not newline delimited.

A ZSON UTF-8 input is organized as a
sequence of one or more values optionally separated by and interspersed
with arbitrary and ignored whitespace.
Single-line (`//`) and multi-line (`/* ... */`) comments are
treated like whitespace and ignored.

All subsequent references to characters and strings in this section refer to
the Unicode code points that result when the stream is decoded.
If a ZSON input includes data that is not valid UTF-8, the input is invalid.

### 3.1 Identifiers

ZSON identifiers are used in several contexts, as names of:
* unquoted fields,
* unquoted enum elements, and
* external type definitions.

Identifiers are case-sensitive and can contain Unicode letters, `$`, `_`,
and digits (0-9), but may not start with a digit.  An identifier cannot be
`true`, `false`, or `null`.

### 3.2 Type Decorators

Any value may be explicitly typed by tagging it with a type decorator.
The syntax for a decorator is a parenthesized type, as in
```
<value> ( <decorator> )
```
where a `<decorator>` is either a type or a type definition.

It is an error for the decorator to be type incompatible with its referenced value.  

> TBD: define precisely the notion of type compatibility

#### 3.2.1 Type Definitions

New type names are created by binding a name to a type with an assignment decorator
of the form
```
<value> (= <type-name> )
```
This creates a new type whose name is given by the type name and whose
type is equivalent to the type of `<value>`.  This new
type may then be used anywhere a type may appear.  The name
of the type definition
must not be equal to any of the primitive type names.

A type definition may also appear inside a decorator as in
```
<type-name> = ( <type> )
```
where the result of this expression is the newly named type.
With this syntax, you can create a new type and decorate a value
as follows
```
<value> ( <type-name> = ( <type> ) )
```
e.g.,
```
80 (port=(uint16))
````
is the value 80 of type "port", where "port" is a type name bound to `uint16`.

The abbreviated form `(=<type-name>)` may be used whenever a type value is
_self describing_ in the sense that its type name can be entirely derived
from its value, e.g., a record type can be derived from a record value
because all of the field names and type names are present in the value, but
an enum type cannot be derived from an enum value because not all the enumerated
names are present in the value.  In the the latter case, the long form
`(<type-name>=(<type>))` must be used.

It is an error for an external type to be defined to a different type
than its previous definition though multiple definitions of the same
type are legal (thereby allowing for concatenation of otherwise
independent sequences).

One decorator is allowed per value except for nested type-union values, which
may include additional decorators to successively refine the union type for union values
that live inside other union types. This allows an already-decorated value to be
further decorated with its union type and provides a means to distinguish
a union value's precise member type when it is otherwise ambiguous as described in
[Section 3.4.4](#344-union-value).

### 3.3 Primitive Values

There are 23 types of primitive values with syntax defined as follows:

| Type       | Value Syntax                                                  |
|------------|---------------------------------------------------------------|
| `uint8`    | decimal string representation of any unsigned, 8-bit integer  |
| `uint16`   | decimal string representation of any unsigned, 16-bit integer |
| `uint32`   | decimal string representation of any unsigned, 32-bit integer |
| `uint64`   | decimal string representation of any unsigned, 64-bit integer |
| `int8`     | decimal string representation of any signed, 8-bit integer    |
| `int16`    | decimal string representation of any signed, 16-bit integer   |
| `int32`    | decimal string representation of any signed, 32-bit integer   |
| `int64`    | decimal string representation of any signed, 64-bit integer   |
| `duration` | a _duration string_ representing signed 64-bit nanoseconds |
| `time`     | an RFC 3339 UTC data/time string representing signed 64-bit nanoseconds from epoch |
| `float16`  | a _non-integer string_ representing an IEEE-754 binary16 value |
| `float32`  | a _non-integer string_ representing an IEEE-754 binary32 value |
| `float64`  | a _non-integer string_ representing an IEEE-754 binary64 value |
| `decimal`  | a _non-integer string_ representing an IEEE-754 decimal128 value |
| `bool`     | the string `true` or `false` |
| `bytes`    | a sequence of bytes encoded as a hexadecimal string prefixed with `0x` |
| `string`   | a double-quoted or backtick-quoted UTF-8 string |
| `bstring`  | a doubled-quoted UTF-8 string with `\x` escapes of non-UTF binary data |
| `ip`       | a string representing an IP address in [IPv4 or IPv6 format](https://tools.ietf.org/html/draft-main-ipaddr-text-rep-02#section-3) |
| `net`      | a string in CIDR notation representing an IP address and prefix length as defined in RFC 4632 and RFC 4291. |
| `type`     | a string in canonical form as described in [Section 3.5](#35-type-value) |
| `error`    | a UTF-8 byte sequence of string of error message|
| `null`     | the string `null` |

The format of a _duration string_
is an optionally-signed sequence of decimal numbers,
each with optional fraction and a unit suffix,
such as "300ms", "-1.5h" or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".

The format of floating point values is a _non-integer string_
conforming to any floating point representation that cannot be
interpreted as an integer, e.g., `1.` or `1.0` instead of
`1` or `1e3` instead of `1000`.  Unlike JSON, a floating point number can
also be one of:
`Inf`, `+Inf`, `-Inf`, or `Nan`.

A string may be backtick-quoted with the backtick character `` ` ``.
None of the text between backticks is escaped, but by default, any newlines
followed by whitespace are converted to a single newline and the first
newline of the string is deleted.  To avoid this automatic deletion and
preserve indentation, the backtick-quoted string can be preceded with `=>`.

Of the 23 primitive types, eleven of them represent _implied-type_ values:
`int64`, `time`, `duration`, `float64`, `bool`, `bytes`, `string`, `ip`, `net`, `type`, and `null`.
Values for these types are determined by the syntax of the value and
thus do not need decorators to clarify the underlying type, e.g.,
```
123 (int64)
```
is the same as `123`.

Values that do not have implied types must include a type decorator to clarify
its type or appear in a context for which its type is defined (i.e., as a field
value in a record, as an element in an array, etc).

> Note that `time` values correspond to 64-bit epoch nanoseconds and thus
> not all possible RFC 3339 date/time strings are valid.  In addition,
> nanosecond epoch times overflow on April 11, 2262.
> For the world of 2262, a new epoch can be created well in advance
> and the old time epoch and new time epoch can live side by side with
> the old using a typedef for the new epoch time aliased to the old `time`.
> An app that wants more than 64 bits of timestamp precision can always use
> a typedef to a `bytes` type and do its own conversions to and from the
> corresponding bytes values.

#### 3.3.1 String Escape Rules

Double-quoted `string` syntax is the same as that of JSON as described
[RFC 8529](https://tools.ietf.org/html/rfc8529), specifically:

* The sequence `\uhhhh` where each `h` is a hexadecimal digit represents
  the Unicode code point corresponding to the given
  4-digit (hexadecimal) number, or:
* `\u{h*}` where there are from 1 to 6 hexadecimal digits inside the
  brackets represents the Unicode code point corresponding to the given
  hexadecimal number.

`\u` followed by anything that does not conform to the above syntax
is not a valid escape sequence.  The behavior of an implementation
that encounters such invalid sequences in a `string` type is undefined.

These escaping rules apply also to quoted field names in record values and
record types.

Doubled-quoted `bstring` values may also included embedded binary data
using the hex escape syntax, i.e., `\xhh` where `h` is a hexadecimal digit.
This allows binary data that does not conform to a valid UTF-8 character encoding
to be embedded in the `bstring` data type.
`\x` followed by anything other than two hexadecimal digits is not a valid
escape sequence. The behavior of an implementation that encounters such
invalid sequences in a `bstring` type is undefined.

Additionally, the backslash character itself (U+3B) may be represented
by a sequence of two consecutive backslash characters.  In other words,
the `bstring` values `\\` and `\x3b` are equivalent and both represent
a single backslash character.

### 3.4 Complex Values

Complex values are built from primitive values and/or other complex values
and each conform to one of six complex types:  _record_, _array_, _set_,
_union_, _enum_, and _map_.

#### 3.4.1 Record Value

A record value has the following syntax:
```
{ <name> : <value>, <name> : <value>, ... }
```
where `<name>` is either an identifier or a quoted string and `<value>` is
any optionally-decorated ZSON value inclusive of other records.
There may be zero or more key/values pairs.

Any value of a field may have an ambiguous type, in which case
the record value must include a decorator, e.g., of the form
```
{ <name> : <value>, <name> : <value>, ... } ( <decorator> )
```
Similarly, a record value may omit the field names when decorated with
a record type value:
```
{ <value>, <value>, ... } ( <decorator> )
```

#### 3.4.2 Array Value

An array value has the following syntax:
```
[ <value>, <value>, ... ]
```
A type decorator applied to an array must be an array type.
If the elements of the array are not of uniform type, then the implied type of
the array elements is a union of the types ordered in the sequence they are encountered.

An array value may be empty.  An empty array value without a type decorator is
presumed to be an empty array of type `null`.

#### 3.4.3 Set Value

A set value has the following syntax:
```
|[ <value>, <value>, ... ]|
```
where the indicated values must be distinct.
A type decorator applied to a set must be a set type.
If the elements of the set are not of uniform type, then the implied type of
the set elements is a union of the types ordered in the sequence they are encountered.

A set value may be empty.  An empty set value without a type decorator is
presumed to be an empty set of type `null`.

#### 3.4.4 Union Value

A union value is simply a value that conforms with a union type.
If the value appears in a context in which the type has not been established,
then the value must be decorated with the union type.

A union type decorator is simply a list of the types that comprise the union
and has the form
```
( <type> , <type> ... )
```
where there are at least two types in the comma separator list of types.

For example,
```
"hello, world" (int32, string)
```
is the `string` value of union type comprising the sub-types `int32` and `string`
Likewise, this is an integer value of the same union:
```
123 (int32, string)
```
Where there is ambiguity, a decorator may resolve the ambiguity as in
```
123 (int8) (int32, int8)
```
Where a union value is inside of nested union types, multiple decorators are
needed to resolve the ambiguity, e.g.,
```
"hello, world" (int32, string) ((int32,string),[int32])
```

> TBD: list the ambiguous possibilities so this is clear.  I think they are
> float16, float32, (u)int8, (u)int16, (u)int32, and uint64 as well as union
> values inside of union values.

#### 3.4.5 Enum Value

An enum type represents a named set of values where enum values are
referenced by name.  The simple form of an
enum is a list of names, where the values are of type `int64` but
enums may be defined as set of values of an arbitrary type.

An enum value has the form
```
<name>
```
where the name is either an identifier or a quoted string and it uniquely
names one of the enum elements.

Such a value must appear in a context where the enum type is known, i.e.,
with an explicit enum type decorator or within a complex type where the
contained enum type is defined by the complex type.

When an enum name is `true`, `false`, or `null`, it must be quoted.

A sequence of enum values might look like this:
```
HEADS (flip=(<HEADS,TAILS>))
TAILS (flip)
HEADS (flip)
```

#### 3.4.6 Map Value

A map value has the following syntax:
```
|{ {<key>, <value>}, {<key>, <value>}, ... }|
```
A type decorator applied to a map can either be one element, referring to a
map type, or two elements referring to the type of the keys and type of the values.

A map value may be empty.  An empty map value without a type decorator is
presumed to be an empty map of type (`null`, `null`).

#### 3.4.7 Type Value

The type of a type value is `type` while its value is depicted by parenthesizing
its type description (as defined in [Section 3.5](#35-type-syntax).  For example,
a type value of a record with a single field called `t` of type `type` would look
like this:
```
{ t: (string) (type) }
```
Since type values have implied types, the `type` type decorator can be omitted:
```
{ t: (string) }
```
Now supposing we created a second field called `t2` whose type is
computed by introspecting the type of `t`.  This result is
```
{
    t: (string),
    t2: (type)
}
```

### 3.5 Type Syntax

The syntax of a type mirrors the value syntax.

A primitive type is the name of the primitive type, i.e., `string`,
`uint16`, etc.

The syntax of complex types parallels the syntax of complex values.

#### 3.5.1 Record Type

A _record type_ has the form:
```
{ <name> : <type>, <name> : <type>, ... }
```
where `<type>` is any type.  The order of the columns is significant,
e.g., type `{a:int32,b:int32}` is distinct from type `{b:int32,a:int32}`.
In contrast to schema abstractions in other formats, ZSON has no way to mark
a field optional as all fields are, in a sense optional: any field can be
encoded with a null value.  If an instance of a record value omits a value
by dropping the field altogether rather than using a null, then that record
value corresponds to a different record type that elides the field in question.

#### 3.5.2 Array Type

An _array type_ has the form:
```
[ <type> ]
```

#### 3.5.3 Set Type

A _set type_ has the form:
```
|[ <type> ]|
```

#### 3.5.4 Union Type

A _union type_ has the form:
```
( <type>, <type>, ... )
```
where there are at least two types in the list.

#### 3.5.5 Enum Type

An _enum type_ has two forms.  The simple form is:
```
< <identifier>, <identifier>, ... >
```
and the complex form is:
```
< <identifier>:<value>, <identifier>=<value>, ... >
```
In the same form, the underlying enum value is equal to its positional
index in the list of identifiers as an uint64 type.

#### 3.5.6 Map Type

A _map type_ has the form:
```
|{ <key-type>, <value-type> }|
```
where `<key-type>` is the type of the keys and `<value-type>` is the
type of the values.

#### 3.5.7 Type Type

The "type" type represents value and its syntax is simply `type`.

#### 3.5.8 Named Type

Any type name created with a type definition is referred to
simply with the same identifier used in its definition.

Type values may refer to external type tames and may elide the definition
fo the external type when the type definition for that name is known,
e.g., if `conn` is a type name, then
```
[conn]
```
is an array of elements of type `conn`.

The canonical form a type value includes the definitions of any and all referenced
types in the value using the embedded type definition syntax:
```
<name> = ( <type> )
```
where `<name>` is a type name or integer, e.g.,
```
conn=({ info:string, src:(socket=({ addr:ip, port:uint16 }), dst:socket })
```
Types in canonical form can be decoded and interpreted independently
of a type context.

A type name has the same form as an identifier except the characters
`/` and `.` are also permitted.

### 3.6 Null Value

The null value is represented by the string `null`.

Any value in ZSON can take on a null representation.  It is up to an
implementation to decide how external data structures map into and
out of values with nulls.  Typically, a null value means either the
zero value or, in the case of record fields, an optional field whose
value is not present, though these semantics are not explicitly
defined by ZSON.

## 4. Examples

> TBD: Add a range of helpful examples and also some that cover the more obscure corner cases.
> Example of pico-second timestamp.

### zeek
```
{
    _path: "conn",
    ts: 2018-03-24T17:15:20.600725Z,
    uid: "C1zOivgBT6dBmknqk" (bstring),
    id: {
        orig_h: 10.47.1.152,
        orig_p: 49562 (port=(uint16)),
        resp_h: 23.217.103.245,
        resp_p: 80 (port)
    } (=0),
    proto: "tcp" (=zenum),
    service: null (bstring),
    duration: 9.698493s (duration),
    orig_bytes: 0 (uint64),
    resp_bytes: 90453565 (uint64),
    conn_state: "SF" (bstring),
    local_orig: null,
    local_resp: null,
    missed_bytes: 0 (uint64),
    history: "^dtAttttFf" (bstring),
    orig_pkts: 57490 (uint64),
    orig_ip_bytes: 2358856 (uint64),
    resp_pkts: 123713 (uint64),
    resp_ip_bytes: 185470730 (uint64),
    tunnel_parents: null (=1)
} (=2)
{
    _path: "conn",
    ts: 2018-03-24T17:15:20.6008Z,
    uid: "CfbnHCmClhWXY99ui",
    id: {
        orig_h: 10.128.0.207,
        orig_p: 13,
        resp_h: 10.47.19.254,
        resp_p: 14
    },
    proto: "icmp",
    service: null,
    duration: 1.278ms,
    orig_bytes: 336,
    resp_bytes: 0,
    conn_state: "OTH",
    local_orig: null,
    local_resp: null,
    missed_bytes: 0,
    history: null,
    orig_pkts: 28,
    orig_ip_bytes: 1120,
    resp_pkts: 0,
    resp_ip_bytes: 0,
    tunnel_parents: null
} (2)
```

### enum

```
{ rank: Ace (24=(<Two,Three,Four,Five,Six,Seven,Eight,Nine,Ten,Jack,Queen,King,Ace>)), suit: H (25=(<Hearts,Diamonds,Spaces,Clubs>)) } (=card)

```
is the same as
```
{ rank: Ace, suit:H } (card=({rank: <Two,Three,Four,Five,Six,Seven,Eight,Nine,Ten,Jack,Queen,King,Ace>, suit:<Hearts,Diamonds,Spaces,Clubs>}))
```

### union

```
{ u: 12 (int32, string, (0=({a:int8,b:ip}), |[0]| ) } (=union_ex)
{ u: "foo" } (union_ex)
{ u: |[ {123,10.0.0.1}, {345,10.0.0.1} ]| } (union_ex)
```

If you have a set of two different types inside of a union that "look the same" then you don't
know which is which so you need a type decorator to distinguish....
```
{ u: |[12, 13 ]| (28=(26=(|[int8])) (26, (27=(|[int16]|)))) } (=union_ex2)
{ u: |[14, 15 ]| (27) } (union_ex2)
```
is the same as
```
{ u: |[12 (int8), 13 ]| (|[int8]|, |[int16]| } (=union_ex2)
{ u: |[14 (int16), 15 ]| } (union_ex2)
```

## 5. Grammar

Here is a left-recursive pseudo-grammar of ZSON.  Note that not all
acceptable inputs are semantically valid as type mismatches may arise.
For example, union and enum values must both appear in a context
the defines their type.

```
<zson> = <zson> <eos> <dec-value> | <zson> <dec-value> | <dec-value>

<eos> = .

<value> = <any> | <any> <val-typedef> | <any> <decorators>

<val-typedef> = "(" "=" <type-name> ")"

<decorators> = "(" <type> ")" | <decorators> "(" <type> ")"

<any> = <primitive> | <record> | <array> | <set> |
            <union> | <enum> | <map> | <type-val>

<primitive> = primitive value as defined above

<record> = "{" <flist> "}"  |  "{"  "}"

<flist> = <flist> "," <field> | <field>

<field> = <field-name> ":" <value> | <value>

<field-name> = <identifier> | <quoted-string>

<quoted-string> = quoted string as defined above

<identifier> = as defined above

<array> = "[" <vlist> "]"  |  "["  "]"

<vlist> = <vlist> "," <value> | <value>

<set> = "|[" <vlist> "]|"  |  "|["  "]|"

<union> = <value>

<enum> = <field-name>

<map> = "|{" <mlist> "}|"  |  "|{"  "}|"

<mlist> = <mvalue> | <mlist> "," <mvalue>

<mvalue> = "{" <value> "," <value> "}"

<type-value> = "(" <type> ")"

<type> = <primitive-type> | <record-type> | <array-type> | <set-type> |
            <union-type> | <enum-type> | <map-type> | <type-type> |
            <type-def> | <type-name>

<primitive-type> = uint8 | uint16 | etc. as defined above including "type"

<record-type> = "{" <tflist> "}"  |  "{" "}"

<tflist> = <tflist> "," <tfield> | <tfield>

<tfield> = <field-name> ":" <type>

<array-type> = "[" <type> "]"  |  "[" "]"

<set-type> = "|[" <type> "]|"  |  "|[" "]|"

<union-type> = "(" <type> "," <tlist> ")"

<tlist> = <tlist> "," <type> | <type>

<enum-type> = "<" <flist> ">"

<map-type> = "{" <type> "," <type> "}"

<type-def> = <identifier> = <type-type>

<type-name> = as defined above
```
