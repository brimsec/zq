# Data Types

Comprehensive documentation for working with data types in ZQL is still a work
in progress. In the meantime, here's a few tips to get started with.

* Values read in by `zq` are stored internally and treated in expressions using one of the data types described in the [ZNG Value Messages](../../../zng/docs/spec.md#32-value-messages) section of the ZNG spec.
* See the [Equivalent Types](../../../zng/docs/zeek-compat.md#equivalent-types) table for details on which ZNG data types correspond to the [data types](https://docs.zeek.org/en/current/script-reference/types.html) that appear in Zeek logs.
* ZQL provides a [type casting](https://en.wikipedia.org/wiki/Type_conversion) syntax using `:` followed by a ZNG data type.

#### Example:

In the Zeek `ntp` log, the field `ref_id` is of Zeek's `string` type, but is often populated with a value that happens to be an IP address. When treated as a string, the attempted CIDR match in the following ZQL would be unsuccessful and no events would be counted.

```
zq -f table 'ref_id in 83.162.0.0/16 | count()' ntp.log.gz
```

However, if we cast it to an `ip` type, now the CIDR match is successful. The `bad cast` warning on stderr tells us that some of the values for `ref_id` could _not_ be successfully cast to `ip`.

```zq-command
zq -f table 'put ref_id=ref_id:ip | filter ref_id in 83.162.0.0/16 | count()' ntp.log.gz
```

#### Output:
```zq-output
bad cast
COUNT
28
```
