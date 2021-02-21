These entries focus on changes we think are relevant to users of Brim,
zq, or pcap.  For all changes to zqd, its API, or to other components in the
zq repo, check the git log.

## v0.29.0
* zqd: Update Zeek pointer to [v3.2.1-brim10](https://github.com/brimsec/zeek/releases/tag/v3.2.1-brim10) which provides the latest [geolocation](https://github.com/brimsec/brim/wiki/Geolocation) data (#2081)
* zql: Add shaping primitive functions `cast()`, `fill()`, `crop()`, and `order()`, along with `fit()` and `shape()` (#1984, #2059, #2073, #2033)
* zson: Read ZSON incrementally rather than all at once (#2031)
* zson: Tighten whitespace in ZSON `-pretty=0` output (#2030)
* zql: Change parallel graph syntax to use `split` and `=>` (#2037)
* zson: Add `duration` to the implied type list (#2039)
* zq: Fix an issue with [`rename`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#rename) where a subsequent `count()` would return no results (#2046)
* zq: Fix an issue where multiple alias typedefs were generated for the same type, causing a TZNG read failure (#2047)
* zson: Fix an issue with string scanning in the ZSON parser that caused the failure `parse error: parsing string literal` (#2048)
* zq: Fix an issue on Windows where `-` was not being treated as a way to read from stdin (#2061)
* zq: Add support in [`put`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#put) for assigning to `.` and to nested fields (#2018)
* zson: Fix an issue where reading ZSON caused the failure `parse error: mismatched braces while parsing record type` (#2058)
* zson: Fix an issue where casting `null` values to string types caused invalid output (#2077)

## v0.28.0
**NOTE** - Beginning with this release, a subset of the source code in the
[github.com/brimsec/zq](https://github.com/brimsec/zq) GitHub repository is
covered by a source-available style license, the
[Polyform Perimeter License (PPL)](https://polyformproject.org/licenses/perimeter/1.0.0/).
We've moved the PPL-covered code under a `ppl/` directory in the repository.
The majority of our source code retains the existing BSD-3-Clause license.

The overwhelming majority of zq/zqd users and developers will not be impacted
by this change, including those using zq/zqd in commercial settings. The use of
the source-available Polyform Perimeter license prevents use cases like
marketing a work as a "as-a-service" style offering for server components like
zqd while using material covered under the PPL.

In general, we are making this change to ensure technology giants can't use the
PPL-covered code to make replacement offerings of our projects. We believe
users and developers should have access to the source code for our projects,
and we need a sustainable business model to continue funding our work. Using
the source-available Polyform Perimeter license on portions of the source code
lets us realize both. 

For more detail regarding licensing, see the
[CONTRIBUTING.md](https://github.com/brimsec/zq/blob/master/CONTRIBUTING.md)
doc, and feel free to come talk to us on
[Slack](https://www.brimsecurity.com/join-slack/) if you have additional
questions.

---

* zqd: Update Zeek pointer to [v3.2.1-brim9](https://github.com/brimsec/zeek/releases/tag/v3.2.1-brim9) which provides the latest [geolocation](https://github.com/brimsec/brim/wiki/Geolocation) data (#2010)
* zqd: Update Suricata pointer to [v5.0.3-brim1](https://github.com/brimsec/build-suricata/releases/tag/v5.0.3-brim1) which disables checksum checks, allowing for alert creation on more types of pcaps (#1975)
* zson: Update [Zeek Interoperability doc](https://github.com/brimsec/zq/blob/master/zng/docs/zeek-compat.md) to include current ZSON syntax (#1956)
* zq: Ensure the output from the [`fuse`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#fuse) processor is deterministic (#1958)
* zq: Fix an issue where the presence of the Greek µ character caused a ZSON read parsing error (#1967)
* zqd: Fix an issue where Zeek events generated during pcap import and written to an archivestore were only visible after ingest completion (#1973)
* zqd: Change the logger configuration to output stacktraces on messages of level "warn" and higher (#1990)
* zq: Update [performance results](https://github.com/brimsec/zq/blob/master/performance/README.md) to include ZSON read/write (#1974)

## v0.27.1
* zq: Fix an issue where nested nulls caused a panic in CSV output (#1954)

## v0.27.0
* zqd: Update Zeek pointer to [v3.2.1-brim8](https://github.com/brimsec/zeek/releases/tag/v3.2.1-brim8) which provides the latest [geolocation](https://github.com/brimsec/brim/wiki/Geolocation) data (#1928)
* zson: Allow characters `.` and `/` in ZSON type names, and fix an issue when accessing fields in aliased records (#1850)
* zson: Add a ZSON marshaler and clean up the ZNG marshaler (#1854)
* zq: Add the `source` field to the JSON typing config to prepare for Zeek v4.x `weird` events (#1884)
* zq: Add initial Z "shaper" for performing ETL on logs at import time (#1870)
* zq: Make all aggregators decomposable (#1893)
* zq/zqd: Invoke [`fuse`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#fuse) automatically when CSV output is requested (#1908)
* zq: Fix an issue where [`fuse`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#fuse) was not preserving record order (#1909)
* zar: Create indices when data is imported or chunks are compacted (#1794)
* zqd: Fix an issue where warnings returned from the `/log/path` endpoint were being dropped (#1903)
* zq: Fix an issue where an attempted search of an empty record caused a panic (#1911)
* zq: Fix an issue where a top-level field in a Zeek TSV log was incorrectly read into a nested record (#1930)
* zq: Fix an issue where files could not be opened from Windows UNC paths (#1929)

## v0.26.0
* zqd: Update Zeek pointer to [v3.2.1-brim7](https://github.com/brimsec/zeek/releases/tag/v3.2.1-brim7) which provides the latest [geolocation](https://github.com/brimsec/brim/wiki/Geolocation) data (#1855)
* zq: Improve the error message shown when row size exceeds max read buffer (#1808)
* zqd: Remove `listen -pprof` flag (profiling data is now always made available) (#1800)
* zson: Add initial ZSON parser and reader (#1806, #1829, #1830, #1832)
* zar: Use a newly-created index package to create archive indices (#1745)
* zq: Fix issues with incorrectly-formatted CSV output (#1828, #1818, #1827)
* zq: Add support for inferring data types of "extra" fields in imported NDJSON (#1842)
* zqd: Send a warning when unknown fields are encountered in NDJSON logs generated from pcap ingest (i.e. Suricata) (#1847)
* zq: Add NDJSON typing configuration for the Suricata "vlan" field (#1851)

## v0.25.0
* zqd: Update Zeek pointer to [v3.2.1-brim6](https://github.com/brimsec/zeek/releases/tag/v3.2.1-brim6) which provides the latest [geolocation](https://github.com/brimsec/brim/wiki/Geolocation) data (#1795)
* zqd: Update Suricata pointer to [v5.0.3-brimpre2](https://github.com/brimsec/build-suricata/releases/tag/v5.0.3-brimpre2) to generate alerts for imported pcaps (#1729)
* zqd: Make some columns more prominent (moved leftward) in Suricata alert records (#1749)
* zq: Fix an issue where returned errors could cause a panic due to type mismatches (#1720, #1727, #1728, #1740, #1773)
* python: Fix an issue where the [Python client](https://medium.com/brim-securitys-knowledge-funnel/visualizing-ip-traffic-with-brim-zeek-and-networkx-3844a4c25a2f) did not generate an error when `zqd` was absent (#1711)
* zql: Allow the `len()` function to work on `ip` and `net` types (#1725)
* zson: Add a [draft specification](https://github.com/brimsec/zq/blob/master/zng/docs/zson.md) of the new ZSON format (#1715, #1735, #1741, #1765)
* zng: Add support for marshaling of `time` values (#1743)
* zar: Fix an issue where a `couldn't read trailer` failure was observed during a `zar zq` query (#1748)
* zar: Fix an issue where `zar import` of a 14 GB data set triggered a SEGV (#1766)
* zql: Add a new [`drop`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#drop) processor, which replaces `cut -c` (#1773)
* zql: Add a new [`pick`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#pick) processor, which acts like a stricter [`cut`](https://github.com/brimsec/zq/tree/master/zql/docs/processors#cut) (#1773, #1788)
* zqd: Improve performance when listing Spaces via the API (#1779, #1786)

## v0.24.0
* zq: Update Zeek pointer to [v3.2.1-brim5](https://github.com/brimsec/zeek/releases/tag/v3.2.1-brim5) which provides the latest [geolocation](https://github.com/brimsec/brim/wiki/Geolocation) data (#1713)
* zql: For functions, introduce "snake case" names and deprecate package syntax (#1575, #1609)
* zql: Add a `cut()` function (#1585)
* zar: Allow `zar import` of multiple paths (#1582)
* zar: Fix an issue where a bare word `zar zq` search could cause a panic (#1590)
* zq: Update Go dependency to 1.15 (#1547)
* zar: Fix an issue where `zar zq` yielded incorrect event counts compared to plain `zq` (#1588, #1602)
* zq: Fix a memory bug in `collect()` that caused incorrect results (#1598)
* zqd: Support log imports over the network (#1336)
* zq: Update [performance results](https://github.com/brimsec/zq/blob/master/performance/README.md) to reflect recent improvements (#1605, #1669, #1671)
* zq: Move Zeek & Suricata dependencies into `package.json` so Brim can point to them also (#1607, #1610)
* zql: Add support for [aggregation-less group by](https://github.com/brimsec/zq/tree/master/zql/docs/grouping#example-1-1) (#1615, #1623)
* zqd: Run `suricata-update` at startup when Suricata pcap analysis is enabled (#1586)
* zqd: Add example Prometheus metrics (#1627)
* zq: Fix an issue where doing `put` of a null value caused a crash (#1631)
* zq: Add `-P` flag to connect two or more inputs to a ZQL query that begins with a parallel flow graph (#1628, #1618)
* zql: Add an initial `join` processor (#1632, #1642)
* zar: Fix an issue where consecutive timestamps caused seek index misses (#1634)
* zar: Fix an issue where time grouping was not working correctly for zar archives (#1650)
* zq/zql: Add support for ZQL comments, multi-line queries, and a `-z` flag for reading ZQL from a file (#1654)
* zqd: Automatically compact data via a background task (#1625)
* zq: Make ordered merge deterministic (#1663)
* zq: Fix a performance regression (#1672)
* zq: Fix an issue where the JavaScript and Go versions of ASTs could differ (#1665)
* zq: Fix an issue where a lone hyphen in an NDJSON value was output incorrectly (#1673)
* zq: Add an experimental writer for a new format called ZSON (#1681)
* zar: Fix an issue during import that could buffer too much data (#1652, #1696)
* zql: Add a `network_of()` function for mapping IP addresses to CIDR nets (#1700)
* zql: Add a [docs example](https://github.com/brimsec/zq/tree/master/zql/docs/grouping#example-4) showing `by` grouping with non-present fields (#1703)

## v0.23.0
* zql: Add `week` as a unit for [time grouping with `every`](https://github.com/brimsec/zq/tree/master/zql/docs/grouping#time-grouping---every) (#1374)
* zq: Fix an issue where a `null` value in a [JSON type definition](https://github.com/brimsec/zq/blob/master/zeek/README.md) caused a failure without an error message (#1377)
* zq: Add [`zst` format](https://github.com/brimsec/zq/blob/master/zst/README.md) to `-i` and `-f` command-line help (#1384)
* zq: ZNG spec and `zq` updates to introduce the beta ZNG storage format (#1375, #1415, #1394, #1457, #1512, #1523, #1529), also adddressing the following:
   * New data type `bytes` for storing sequences of bytes encoded as base64 (#1315)
   * Improvements to the `enum` data type (#1314)
   * Special characters like `.` and `@` may now appear in field names (#1291)
   * A `set` may now only support elements of a single type (#1220, #1515)
   * Remove the `byte` type from the spec in favor of `uint8` (#1316)
   * New data type `map`, which is like `set` but the contents are key value pairs where only keys need to be unique and the canonical order is based on the key order (#1317)
   * First-class ZNG types (#1365)
   * New numeric data types `float16` and `float32` (not yet implemented in `zq`) (#1312, #1514)
   * New numeric data type `decimal` (not yet implemented in `zq`) (#1522)
* zq: Add backward compatibility for reading the alpha ZNG storage format (#1386, #1392, #1393, #1441)
* zqd: Check and convert alpha ZNG filestores to beta ZNG (#1574, #1576)
* zq: Fix an issue where spill-to-disk file names could collide (#1391)
* zq: Allow the [`fuse` processor](https://github.com/brimsec/zq/tree/master/zql/docs/processors#fuse) to spill-to-disk to avoid memory limitations (#1355, #1402)
* zq: No longer require `_path` as a first column in a [JSON type definition](https://github.com/brimsec/zq/blob/master/zeek/README.md) (#1370)
* zql: Improve ZQL docs for [aggregate functions](https://github.com/brimsec/zq/blob/master/zql/docs/aggregate-functions/README.md) and [grouping](https://github.com/brimsec/zq/blob/master/zql/docs/grouping/README.md) (#1385)
* zql: Point links for developer docs at [pkg.go.dev](https://pkg.go.dev/) instead of [godoc.org](https://godoc.org/) (#1401)
* zq: Add support for timestamps with signed timezone offsets (#1389)
* zq: Add a [JSON type definition](https://github.com/brimsec/zq/blob/master/zeek/README.md) for alert events in [Suricata EVE logs](https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html) (#1400)
* zq: Update the [ZNG over JSON (ZJSON)](https://github.com/brimsec/zq/blob/master/zng/docs/zng-over-json.md) spec and implementation (#1299)
* zar: Use buffered streaming for archive import (#1397)
* zq: Add an `ast` command that prints parsed ZQL as its underlying JSON object (#1416)
* zar: Fix an issue where `zar` would SEGV when attempting to query a non-existent index (#1449)
* zql: Allow sort by expressions and make `put`/`cut` expressions more flexible (#1468)
* zar: Move where chunk metadata is stored (#1461, #1528, #1539)
* zar: Adjust the `-ranges` option on `zar ls` and `zar rm` (#1472)
* zq: Choose default memory limits for `sort` & `fuse` based on the amount of system memory (#1413)
* zapi: Fix an issue where `create` and `find` were erroneously registered as root-level commands (#1477)
* zqd: Support pcap ingest into archive Spaces (#1450)
* zql: Add [`where` filtering](https://github.com/brimsec/zq/tree/master/zql/docs/aggregate-functions#where-filtering) for use with aggregate functions (#1490, #1481, #1533)
* zql: Add [`union()`](https://github.com/brimsec/zq/tree/master/zql/docs/aggregate-functions#union) aggregate function (#1493, #1534)
* zql: Add [`collect()`](https://github.com/brimsec/zq/tree/master/zql/docs/aggregate-functions#collect) aggregate function (#1496, #1534)
* zql: Add [`and()`](https://github.com/brimsec/zq/tree/master/zql/docs/aggregate-functions#and) and [`or()`](https://github.com/brimsec/zq/tree/master/zql/docs/aggregate-functions#or) aggregate functions (#1497, #1534)
* zq: Fix an issue where searches did not match field names of records with unset values (#1511)
* zq: Fix an issue where searches were not reaching into records inside arrays (#1516)
* zar: Support microindexes created with a sorted flow of records in descending order (#1526)
* zapi: Allow `zapi post` of S3 objects (#1532)
* zar: Add the `zar compact` command for combining overlapping chunk files into single chunks (#1531)
* zar: Use chunk seek index for searching chunk data files (#1537)
* zq: Make timestamp output formatting consistent (#1550, #1551, #1557)
* zq: Update LZ4 dependency to improve performance (#1556)
* zq: Fix an issue where TZNG fields containing `]` were treated as a syntax error (#1561)
* zar: Fix an issue where the `zar import` target size didn't take compression into account (#1565)
* zapi: Add a `-stats` option to `zapi pcappost` (#1538)
* zqd: Add a Python `zqd` API client for use with tools like [JupyterLab](https://jupyterlab.readthedocs.io/en/stable/) (#1564)

## v0.22.0
* zq: Change the implementation of the `union` type to conform with the [ZNG spec](https://github.com/brimsec/zq/blob/master/zng/docs/spec.md#3114-union-typedef) (#1245)
* zq: Make options/flags and version reporting consistent across CLI tools (#1249, #1254, #1256, #1296, #1323, #1334, #1328)
* zqd: Fix an issue that was preventing flows in nanosecond pcaps from opening in Brim (#1243, #1241)
* zq: Fix an issue where the TZNG reader did not recognize a bad record type as a syntax error (#1260)
* zq: Add a CSV writer (`-f csv`) (#1267, #1300)
* zqd: Add an endpoint for returning results in CSV format (#1280)
* zqd: Add an endpoint for returning results in NDJSON format (#1283)
* zapi: Add an option to return results as a JSON array (`-e json`) (#1285)
* zapi: Add output format options/flags to `zapi get` (#1278)
* zqd: Add an endpoint for creating/querying search indexes (#1272)
* zapi: Add commands `zapi index create|find` for creating/querying search indexes (#1289)
* pcap: Mention ICMP protocol filtering (`-p icmp`) in help text (#1281)
* zq: Point to new Slack community URL https://www.brimsecurity.com/join-slack/ in docs (#1304)
* zqd: Fix an issue where starting `zqd listen` created excess error messages when subdirectories were present (#1303)
* zql: Add the [`fuse` processor](https://github.com/brimsec/zq/tree/master/zql/docs/processors#fuse) for unifying records under a single schema (#1310, #1319, #1324)
* zql: Fix broken links in documentation (#1321, #1339)
* zst: Introduce the [ZST format](https://github.com/brimsec/zq/blob/master/zst/README.md) for columnar data based on ZNG (#1268, #1338)
* pcap: Fix an issue where certain pcapng files could fail import with a `bad option length` error (#1341)
* zql: [Document the `**` operator](https://github.com/brimsec/zq/tree/master/zql/docs/search-syntax#wildcard-field-names) for type-sepcific searches that look within nested records (#1337)
* zar: Change the archive data file layout to prepare for handing chunk files with overlapping ranges and improved S3 support (#1330)
* zar: Support archive data files with overlapping time spans (#1348)
* zqd: Add a page containing guidance for users that directly access the root `zqd` endpoint in a browser (#1350)
* pcap: Add a `pcap info` command to print summary/debug details about a packet capture file (#1354)
* zqd: Fix an issue with empty records (#1353)
* zq: Fix an issue where interrupted aggregations could leave behind temporary files (#1357)
* zng: Add a marshaler to generate ZNG streams from native Go values (#1327)

## v0.21.0
* zq: Improve performance by making fewer API calls in S3 reader (#1191)
* zq: Use memory more efficiently by reducing allocations (#1190, #1201)
* zqd: Fix an issue where a pcap moved/deleted after import caused a 404 response and white screen in Brim (#1198)
* zqd: Include details on [adding observability](https://github.com/brimsec/zq/tree/master/k8s#adding-observability) to the docs for running `zqd` in Kubernetes (#1173)
* zq: Improve performance by removing unnecessary type checks (#1192, #1205)
* zq: Add additional Boyer-Moore optimizations to improve search performance (#1188)
* zq: Fix an issue where data import would sometimes fail with a "too many files" error (#1210)
* zq: Fix an issue where error messages sometimes incorrectly contained the text "(MISSING)" (#1199)
* zq: Fix an issue where non-adjacent record fields in Zeek TSV logs could not be read (#1225, #1218)
* zql: Fix an issue where `cut -c` sometimes returned a "bad uvarint" error (#1227)
* zq: Add support for empty ZNG records and empty NDJSON objects (#1228)
* zng: Fix the tag value examples in the [ZNG spec](https://github.com/brimsec/zq/blob/master/zng/docs/spec.md) (#1230)
* zq: Update LZ4 dependency to eliminate some memory allocations (#1232)
* zar: Add a `-sortmem` flag to allow `zar import` to use more memory to improve performance (#1203)
* zqd: Fix an issue where file paths containing URI escape codes could not be opened in Brim (#1238)

## v0.20.0
* zqd: Publish initial [docs](https://github.com/brimsec/zq/blob/master/k8s/README.md) for running `zqd` in Kubernetes (#1101)
* zq: Provide a better error message when an invalid IP address is parsed (#1106)
* zar: Use single files for microindexes (#1110)
* zar: Fix an issue where `zar index` could not handle more than 5 "levels" (#1119)
* zqd: Fix an issue where `zapi pcappost` incorrectly reported a canceled operation as a Zeek exit (#1139)
* zar: Add support for empty microindexes, also fixing an issue where `zar index` left behind empty files after an error (#1136)
* zar: Add `zar map` to handle "for each file" operations (#1138, #1148)
* zq: Add Boyer-Moore filter optimization to ZNG scanner to improve performance (#1080)
* zar: Change "zdx" to "microindex" (#1150)
* zar: Update the [`zar` README](https://github.com/brimsec/zq/blob/master/ppl/cmd/zar/README.md) to reflect recent changes in commands/output (#1149)
* zqd: Fix an issue where text stack traces could leak into ZJSON response streams (#1166)
* zq: Fix an issue where an error "slice bounds out of range" would be triggered during attempted type conversion (#1158)
* pcap: Fix an issue with pcapng files that have extra bytes at end-of-file (#1178)
* zqd: Add a hidden `-brimfd` flag to `zqd listen` so that `zqd` can close gracefully if Brim is terminated abruptly (#1184)
* zar: Perform `zar zq` queries concurrently where possible (#1165, #1145, #1138, #1074)

## v0.19.1

* zq: Move third party license texts in zq repo to a single [acknowledgments.txt](https://github.com/brimsec/zq/blob/master/acknowledgments.txt) file (#1107)
* zq: Automatically load AWS config from shared config file `~/.aws/config` by default (#1109)
* zqd: Fix an issue with excess characters in Space names after upgrade (#1112)

## v0.19.0
* zq: ZNG output is now LZ4-compressed by default (#1050, #1064, #1063, [ZNG spec](https://github.com/brimsec/zq/blob/master/zng/docs/spec.md#313-compressed-value-message-block))
* zar: Adjust import size threshold to account for compression (#1082)
* zqd: Support starting `zqd` with datapath set to an S3 path (#1072)
* zq: Fix an issue with panics during pcap import (#1090)
* zq: Fix an issue where spilled records were not cleaned up if `zq` was interrupted (#1093, #1099)
* zqd: Add `-loglevel` flag (#1088)
* zq: Update help text for `zar` commands to mention S3, and other improvements (#1094)
* pcap: Fix an out-of-memory issue during import of very large pcaps (#1096)

## v0.18.0
* zql: Fix an issue where data type casting was not working in Brim (#1008)
* zql: Add a new [`rename` processor](https://github.com/brimsec/zq/tree/master/zql/docs/processors#rename) to rename fields in a record (#998, #1038)
* zqd: Fix an issue where API responses were being blocked in Brim due to commas in Content-Disposition headers (#1014) 
* zq: Improve error messaging on S3 object-not-found (#1019)
* zapi: Fix an issue where `pcappost` run with `-f` and an existing Space name caused a panic (#1042)
* zqd: Add a `-prometheus` option to add [Prometheus](https://prometheus.io/) metrics routes the API (#1046)
* zq: Update [README](https://github.com/brimsec/zq/blob/master/README.md) and add docs for more command-line tools (#1049)

## v0.17.0
* zq: Fix an issue where the inferred JSON reader crashed on multiple nested fields (#948)
* zq: Introduce spill-to-disk groupby for performing very large aggregations (#932, #963)
* zql: Use syntax `c=count()` instead of `count() as c` for naming the field that holds the value returned by an aggregate function (#950)
* zql: Fix an issue where attempts to `tail` too much caused a panic (#958)
* zng: Readability improvements in the [ZNG specification](https://github.com/brimsec/zq/blob/master/zng/docs/spec.md) (#935)
* zql: Fix an issue where use of `cut`, `put`, and `cut` in the same pipeline caused a panic (#980)
* zql: Fix an issue that was preventing the `uniq` processor from  working in the Brim app (#984)
* zq: Fix an issue where spurious type IDs were being created (#964)
* zql: Support renaming a field via the `cut` processor (#969)

## v0.16.0
* zng: Readability improvements in the [ZNG specification](https://github.com/brimsec/zq/blob/master/zng/docs/spec.md) (#897, #910, #917)
* zq: Support directory output to S3 (#898)
* zql: Group-by no longer emits records in "deterministic but undefined" order (#914)
* zqd: Revise constraints on Space names (#853, #926, #944, #945)
* zqd: Fix an issue where a file replacement race could cause an "access is denied" error in Brim during pcap import (#925)
* zng: Revise [Zeek compatibility](https://github.com/brimsec/zq/blob/master/zng/docs/zeek-compat.md) doc (#919)
* zql: Clarify [`cut` processor documentation](https://github.com/brimsec/zq/tree/master/zql/docs/processors#cut) (#924)
* zqd: Fix an issue where an invalid 1970 Space start time could be created in Brim during pcap inport (#938)

## v0.15.0
* pcap: Report more detailed error information (#844)
* zql: Add a new function `Time.trunc()` (#842)
* zql: Support grouping by computed keys (#860)
* zq: Change implementation of `every X` to use a computed groupby key (#893)
* zql: Clean up the [ZQL docs](https://github.com/brimsec/zq/tree/master/zql/docs) (#884)
* zql: Change `cut` processor to emit any matching fields (#899)
* zq: Allow output to an S3 bucket (#889)

## v0.14.0
* zq: Add support for reading from S3 buckets (#733, #780, #783)
* zq: Add initial support for reading Parquet files (only via `-i parquet`, no auto-detection) (#736, #754, #774, #780, #782, #820, #813, #830, #825, #834)
* zq: Fix an issue with reading/writing recursively-nested NDJSON events (#748)
* zqd: Begin using a "runner" to invoke Zeek for processing imported pcaps (#718, #788)
* zq: Fix issues related to reading NDJSON during format detection (#752)
* zqd: Include stack traces on panic errors (#732)
* zq: Handle `\r\n` line endings generated by MinGW (Windows) Zeek (#775)
* zq: Support scientific notation for integer types (#768)
* zql: Add cast syntax to expressions (#765, #784)
* zq: Fix an issue where reads from stdin were described as being from `-` (#777)
* zq: Improve an NDJSON parsing error to be more detailed than "bad format" (#776)
* zjson: Fix an issue with aliases in the zjson writer (#793)
* zq: Fix an issue where typed JSON reads could panic when a field that was expected to contain an array instead contained a scalar (#799)
* zq: Fix an issue with ZNG handling of aliases on records (#801)
* zq: Fix an issue with subnet searches (#807)
* zapi: Introduce `zapi`, a simple CLI for interacting with `zqd` servers (#802, #809, #812)
* zq: Add arguments to generate CPU/memory profiles (#814)
* zql: Introduce time conversion functions (#822)
* zq: Ensure Spaces have non-blank names (#826)

## v0.13.1
* zq: Fix an issue with stream reset that was preventing the pcap button in Brim from activating (#725)
* zql: Allow multiple fields to be written from `put` processor (#697)

## v0.13.0
* zqd: Enable time indexing to provide faster query response in narrower time ranges (#647)
* zql: Make ipv4 subnet bases contain 4 octets to remove ambiguity between fractions & CIDR (#670)
* zq: Use an external sort for large inputs (removes the 10-million line `sort` limit) (#527)
* zq: Fix an issue where duplicate field names could be produced by aggregate functions & group-by (#676)
* zar: Introduce an experimental prototype for working with archived logs
 ([README](https://github.com/brimsec/zq/blob/master/ppl/cmd/zar/README.md)) (#700)
* zq: Support recursive record nesting in Zeek reader/writer (#715)
* zqd: Zeek log import support needed for Brim (#616, #517, #608, #592, #592, #582, #709)

## v0.12.0
* zql: Introduce `=~` and `!~` operators in filters for globs, regexps, and matching addresses against subnets (#604, #620)
* zq: When input auto-detect fails, include each attempted format's error (#616)
* zng: Binary format is now called "ZNG" and text format is called "TZNG" ("BZNG" has been retired) (#621, #630, #656)
* zql: `cut` now has a `-c` option to show all fields _not_ in the provided list (#639, #655)
* zq: Make `-f zng` (binary ZNG) the default `zq` output format, and introduce `-t` as shorthand for `-f tzng` (#654)

## v0.11.1
* zqd: Send HTTP status 200 for successful pcap search (#605)

## v0.11.0
* zql: Improve string search matching on field names (#570)
* pcap: Better handling of empty results (#572)
* zq: Introduce `-e` flag to allow for continued reads during input errors (#577)
* pcap: Allow reading of pcap files that have a capture length that exceeds the original length of the packet (#584)
* zqd: Fix an issue that was causing the histogram to draw incorrectly in Brim app (#602)

## v0.10.0

* zql: Let text searches match field names as well as values (#529)
* zql: Fix an issue where ZQL queries exceeding 255 chars caused a crash (#543)
* zql: Make searches case-insensitive by default (#536)
* Fix an issue where the Zeek reader failed to read whitespace from the rightmost column (#552)

## v0.9.0

* zql: Emit warnings from `put` processor (#477)
* zql: Add string functions (#475)
* zql: Narrow the use of `len()` to only sets/vectors, introduce new functions for string length (#485)
* zql: Add ternary conditional operator (#484)
* zqd: Add waterfall logger (#492)
* zqd: Make http shutdown more graceful (#500)
* zqd: Make space deletion cancel and await other operations (#451)

## v0.8.0

* zql: add the `put` processor that adds or updates fields using a computed
  expression. (#437)
* zql: add functions for use with put, like `Math.min`, `Math.max`, and others.
  (#453, #459, #461, #472)
* zq: support reading ndjson with user supplied type information. (#441)
* Fix an issue reading pcaps with snaplen=0. (#462)

## v0.7.0

* Address ingest issues for packet captures in legacy pcap format.
* Calculate and respond with packet capture time range at the start of ingest,
  so that Brim can immediately display the space's time range.

## v0.6.0

* zq now displays warnings by default; the "-W" flag is removed, replaced by
  the "-q" for quieting warnings.
* Update license to reflect new corporate name.
* Address ingest issues for some pcapng packet captures.
* Address ingest issues for file or path names that required uri encoding.

## v0.5.0

* Support search queries during pcap ingestion.
* Improved error reporting in zqd, especially during pcap ingestion.
* Improved performance of space info api.
* zqd supports ingesting pcapng formatted packet capture files.

## v0.4.0
  
* zqd adds an endpoint to create a new empty space via post
* zqd adds an endpoint to post packet captures that are indexed and turned into Zeek logs

## v0.3.0

* zqd adds -datadir flag for space root directory.
* zqd adds -version flag.
* Add pcap command to interact with packet capture files.

## v0.2.0

* Per-platform binaries will be available as Github release assets.
* zql examples under zql/docs are now verified via `make test-heavy`.
* Negative integers and floats are accepted in zql expressions.
* Internal integer types now match the ZNG specification.
* Fixed comparisons of aliased types.

## v0.1.0

* zq moves from github.com/mccanne/zq to github.com/brimsec/zq.
* Parser and AST moved to zq repo from github.com/looky-cloud/lookytalk.
* Query language name changed to ZQL.
* ZNG specification added.

## v0.0.1

* Initial release of zq.
