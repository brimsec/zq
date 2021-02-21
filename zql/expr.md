# expression syntax and searches

> This document describes recent work on unifying the search syntax with
> the expression syntax.  We are checking this markdown file here with a bunch
> of thoughts and notes into master for now with the
> goal of integrating these concepts into the mainline documentation.
> See Issue #2021.

In order to support a mixture of _ad hoc_ search and well-defined analytics,
the zql expression syntax attempts to blend the more informal properties
of keyword search languages with the formal properties of expression syntax
from programming languages.

For example, when searching email, you might say something like
```
john smith
```
to mean emails relating to "John Smith" but you realize you got too many
false positives so you refined the search to
```
john smith acme.com
```
becase you know he works at acme.com.  But then you realize he also has a  
personal gmail account, so instead you search for
```
"John Smith"
```
and that's better but still too many false positives.  Finally, you  
refine the search to
```
"John Smith" (acme.com OR gmail.com)
```
and you find what you were looking for.

Now, suppose you were searching a structured database for John Smith.  The SQL
query might look like this:
```
SELECT * FROM Messages
   WHERE LastName='Smith' AND FirstName = "John" AND
     (Email LIKE '*.acme.com' OR Email Like '*.gmail.com')
```
This SQL syntax is great because it's very precise and predictable, but this
comes at more cognitive load and more typing than the ad hoc search query.
If you're writing an analytics query to be saved in a notebook or run from
automation, then the cognitive load is justified but if you are searching for
stuff on an ad hoc basis, the free form syntax is much more productive.

## zql - A Hybrid Approach

Log search and analytics systems came along to fill this gap.
In this approach, you can run a keyword search and send the
results to a
pipeline of operators to transform the search hits to something more
predictable.

In previous approaches, the search syntax is very different from the analytics
syntax and the syntax for expressions can be somewhat cumbersome.

With zql, however, we have strived to blend together the search language
with the expression language where you can enjoy the ease of use of ad hoc,
search-style syntax but blend searches with precision expression syntax
that works both within the search predicate as well as the analytics processing.

For example, suppose you wanted to search certain for zeek http logs
that had some particular string pattern in one of the http headers and an unusually
large request size.  You might say
```
_path=http AND (finance OR sales) request_body_len >= 10*MiB
```
Here, `_path=http` is an exact-match field comparisong between the field
`_path` and the string `"http"`, `(finance OR sales)` is a free-form
text search for either string `"finance"` or `"sales"` and
`request_body_len >= 10*MiB` is boolean expression predicate that matches
any zeek http logs whose field `request_body_len` is larger than 10MiB, where
`MiB` is a constant equal to 2^20.

> NOTE: We don't yet have support for constants like MiB but this will come soon.

Compare this to...
```
_path=http (finance OR sales) request_body_len >= 10*MiB
```
Here, you would expect the concatenation-implies-AND to work for the
 terms `_path=http` and `(finance OR sales)` but this is instead interpreted
 as a reducer called "http" then a syntax error at `request_body_len`.

 > How should we handle this ambiguity?  Right now, we say you need
 > an explicit "and" before an open paren but this could be confusing.
 > Perhaps we could say contatenated-AND is valid only for concatenated
 > keyword search terms?  This might be less confusing and it shouldn't be
 > too hard to implement.

## The ambiguity problem

Getting this all right and balancing the informal syntax with the formal syntax
is a bit tricky.  For example, `*` can mean glob match in a search context or
multiplication in an expression context.  So what should this mean?
```
a=b*c
```
Does this match numeric fields for field `a` that equals field `b` times
`c` or should it match string fields starting with `"b"` and ending with `"c"`?

What about this?
```
a < b * c
```

Or this?
```
query=web.*.com
```

Currently, we're assuming `a=b*c` is a string glob match but `a = b * c`
is `b` times `c` as the spaces make it clear that it is not a glob string.

Likewise, domain names use dotted notation as do record accesses and
numeric IP address. So, clearly, this expression
```
query=acme.com
```
means to match the field called `query` against the string value `"acme.com"`,
but this expression is less clear
```
id.orig_p=id.resp_p
```
In the case of zeek `id` records, the intent here is to match records
in which the originator port and responder port is the same.

Finally, consider these two expressions:
```
_path=conn | count()
count() where _path=conn
```
The intent here is that the first `_path=conn` expression is in the context
of a search while the second is in the context of a boolean expression
embedded in a where clause.  In the unified approach, the where clause is
simply a boolean search expression so you can say
```
count() where acme.com or google.com
```
Consider another examples
```
* | put isConn=_path=conn, isSSL=_path=ssl, portsMatch=id.orig_h=id.orig_p | ...
```
Here, `=` means two different things (assignment and comparison).  The parse
knows by context which is which but it can look a bit funny.  This might
make more sense:
```
* | put isConn=_path==conn, isSSL=_path==ssl, portsMatch=id.orig_h==id.orig_p | ...
```
But now, we don't want to have to say this...
```
_path==conn | ...
```
Again, blending keyword search metaphors with programming language expressions
necessarily creates ambiguities.

## Resolving the ambiguities

To settle all this and still support a nice hybrid language, we define
a set of "shortcuts" that are valid in search expressions (but not
in standard expressions).

> Maybe we should make the shortcuts work for standard expressions too?
> This would be more consistent and probably easier to document and understand
> and you can always "escape out of" the shortcuts with canonical syntax.

The shortcuts will use these definitions:
```
ID = identifier (interpreted as string literal)
DottedID = two or more IDs joined by "." (interpreted as string literal)
```

The shortcuts are:

* RHS of `<lval>=<expr>` is a string iff `<expr>` is an ID or DottedID even
when LHS is something more complicated than a simple field expression, e.g.,
`ip_list[3]=foo` or even `1+1=foo`, which is false (comparing 2 to string "foo"),
which is not the same as the predicate `foo=2`.
* RHS of `<lval>=<glob>` is a regular expression match iff `<glob>` is a glob
style string  (i.e., not to be interpreted as multiplication)
when LHS is something more complicated than a simple field expression, e.g.,
`ip_list[3]=foo` or even `1+1=foo`, which is false (comparing 2 to string "foo"),
which is not the same as the predicate `foo=2`.
* To interpret a standalone ID or DottedID on RHS as record access instead
of string, you simply prepend a ".", e.g., `id.orig_p=.id.resp_p`.  Of course,
this is the same as `.id.orig_p=.id.resp_p`.
* A RHS that is an expression does not ever interpret ID or DottedID as a string,
e.g., in `foo=bar*baz>10`, `bar` and `baz` are field references not strings and
`*` is multiplication not glob match because it appears in the context of a
comparision expression.  On the other hand, for `foo=bar*baz`, the RHS would
be a glob style match for strings beginning with `bar` and ending in `baz`.

> Note: we don't quite have all these rules working yet.  "."prefix
> disambiguation and `1+1=foo` isn't doing the right thing.  The
> expression syntax needs one more pass of re-jiggering.  That said, we have
> no unified (most) generic expression syntax so you can search on  
> expression-oriented boolean predicates.

> Also note: minus sign is no longer allowed as a shortcut RHS string, so
> `acme.com-foo` is always any expression.  We could change this back if we'd like.

For expression context, e.g., RHS of `put` or `cut` assignment or
boolean-expression in `where` clause, these SAME rules apply as the
search predicates.

That said, keyword search does not appear in expression context.
e.g.,
```
* | put x=foo
```
means assign the field foo to x.  The RHS is never a keyword search resulting
in a boolean for matches to the word "foo".   That said, search syntax can
appear inside of an expression with the explicit use of the `match` function,
e.g.,
```
* | put foundIt=match(foo)
```
or from our example above...
```
* | put foundIt=match("John Smith" (acme.com OR gmail.com))
```

> Note: we may want to make `put x=foo==bar` treat bar as a string to be
> consistent with the search shortcuts.  It doesn't work like this now,
> but we could easily make this change.

### `*` and `**` replaced with generators and method chaining

As part of this work, the implementation of `*`, and `**` wildcard matches
has been generalized.

Querying over semi-structured data has been extensively studied in the worlds of
XML and NOSQL databases.
SQL++ has N1QL have
[collection operators](https://docs.couchbase.com/server/current/n1ql/n1ql-language-reference/collectionops.html).

While we were motivated by the approach in these systems, they are very
SQL-oriented and don't match the flow-based programming model of Z.
(It is future work to put a SQL interface onto the Z analytics engine and
perhaps these SQL++ style idioms will come into play here.)

The field wildcard search is a specific-case in the current Z implementation
of operating over semi-structured data, e.g.,
```
*=foo
```
This is really a boolean predicate applied to each field a (short-circuit)
OR-ed together.  This leads one to think that maybe a generator style model
could be used here, where we select values to be "generated" then we operate
on those values using
[fluent-style](https://en.wikipedia.org/wiki/Fluent_interface)
method chaining a la d3, jQuery, react, etc.

For example, `select` could be used to select a sequence of records that
would generate the field values of each record,
```
select(a,b)
```
(where `a` and `b` are expected to be records)
then we could operate on those values with an aggregator, e.g.,
```
sum(select(a,b))
```
Of course, the fields of "." could be selected as follows,
```
sum(select(.))
```
Then a predicate applied to each generated value:
```
sum(select(.).map($=foo)
```
where `$` refers to the "current value" in the generated sequence,
then the results could be aggreagated with an "or" function:
```
or(sum(select(.).map($=foo))
```
which is equivalent to
```
*=foo
```

> Note the compiled optimizes the general structure to something more
> compact and efficient for the common cases like "match any field".

The select syntax needs exploration but the idea is that it generates a
sequence of values that can be operated upon by methods which can modify or
filter the sequence (where `$` refers to the current value in the sequence)
and the resulting sequence can be summarized with an aggregate function.

Selecting a container generates each value in the container (for records,
the top level fields are generated and not recursed into... I was thinking
we could have another variant of select called `traverse` that descends
into records and perhaps has a continuation/halt predicate to control the walk).

Selecting a primitive generates that one value.  But select can take multiple
arguments so you can select a sequence of values.

> Note: currently only record selecting is implemented but these variations
> are pretty straightforward to add.

#### Syntactic Sugar

Once we play around with these generator concepts, we may decide upon syntactic
sugar for common use cases and Z patterns.

We may want to build `any` and `all` boolean expressions from SQL++,
e.g., for addr and nets you could say
```
any(n over nets, addr in n)
```
or
```
all(n over nets, addr in n)
```
This could recurse in the array of arrays case, e.g.,
```
A:[[1,2,3],[4,5],[3,3]]
```
```
any(a over A, any(v over a, v=1))
```
would be true
```
any(a over A, all(v over a, v=3))
```
would also be true but
```
any(a over A, all(v over a, v=1))
```
would be false.

Once we have this, we can define `a in A` to mean the above or a variation
of above where there is flexibility in traversing the nesting as in the
confusing `recursive` flag (it wouldn't be so confusing if there were
precise semantics that were documented like we are trying to do here).

With type values, this pattern also means we can do bare searches based on type:
```
any(addr is typeof(ip) within ., addr=192.168.1.1)
```
where we could have an abbreviation
```
192.168.1.1 in* .
```
where `in*` implies the recursive behavior from before.

To make this all clear, I think what's going on here is we're identifying
sets of things to traverse then we are traversing them with a loop variable
and we're allowing the construct to be recursive.  This means we should
break the pattern into two pieces: (1) an expression syntax to create / refer to
sets of values, and (2) an any/all syntax to apply a predicate to each value
of the set and compute a boolean AND (for all) or a boolean OR (for any) of
each predicate.

is the set of values of type ip nested within `.`  This is perhaps where the
recursive matcher belongs.  Then the above expression can be written as
```
any(addr over types_of(., (ip)), addr=192.168.1.1)
```
> These structures are vectorizable and are predicates that can be
> pushed down into the zst scanner when we get to columnar optimization (well
> after launch of MVP).


### Examples

```
put s=sum(select(.).filter($>0))
put s=sum(select(.).filter(typeof($)={[int64]})).map(sum($))
```

`select` generates the top-level field values of a record.
`traverse` does a dfs traversal of nested records but does not enter  
non-record container-types (see below).

But how do we differentiate this from standard aggregator?
Right now, this compiles to-group-by.
We can distinguish here because the arg must be a generator instead
of a value expression and generators cannot be elements of an expression
(e.g., you can't say `select(.)+1` you have to say `select(.).map($+1)`)

and
```
**=foo
```
is the same as
```
or($.traverse(.).map($=foo))
```

Traversals can be recursive into array of records or array of arrays...
```
sum(x.y.traverse().filter(typeof($)=[int32]).traverse().filter($>100))
```

Collect can be used to put stuff into an array (or array of union)...
```
($g=x.y.traverse(.)).filter($=foo+$g)
```

> TBD: fix collect() reducer to handle mixed-type inputs

> Note: in the implementation, the *parser* knows that something is a
> generator chain because it starts with a keyword that creates a generator
> as generators are not otherwise first-class values.  In the first stab at
> this only select() and traverse() will create the initial generator.
> Then any reducer can be applied to a generated sequence to produce a
> first-class value/result.  In the very first stab, we'll start with select().

Syntactically, we know that a generator-function happens if and only if
we see the construct
```
<gen-expr> . <identifier> ( <args> )
```

> Note because the parser knows what is a generated thing, we can differentiate
> between this and module syntax for function calls if we ever want to do that.

We need to distinguish between:
* global aggregations
* running aggregation inside of expression
* aggregations operating on generated sequences

An array can be used as a generator, e.g., if `a` is an array...
```
select(a).filter($>1)
```

An array constant...

```
select([1,2,3]).filter($>=2)
```
or this can work...
```
c=collect(select({a:1,b:2,c:3}).map($+1))
```

The slice operator works on sequences like this:
```
[1,2,3,4].[1:2]
```
which gives the sequence
```
2,3
```
This can be applied to arrays as well as generators.  In the case of array,
the result is an array (not a generator).  But you can use the array as a source
of a generator expression so you can slice something then operate on the generated
alements like this:
```
collect(select(a[2:4]).map($+1))
```

> NOTE: we might want to make array be an implied sequence if a method is
> applied to them.  Then the system won't know that something is generated
> until runtime but that might be okay.

Or we can distinguish generator idioms from field access are that the
generator operators are reserved keywords, e.g.,
* select
* map
* filter
* join

Search syntax can be applied in expression context with the "match" keyword
```
... | put isGoogle=match(google.com or acme.com) | ...
```

Sub-searches can be triggered with the search keyword where the result
of a search is a
(it would be up to the runtime context to, for instance, apply the primary-key
time window of the outer search to the sub-search, unless somehow overridden).
```
... | put queryMap=map(search(google.com or acme.com | c=count() by q=query)) | ...
```
The `map` aggregator creates a map value.

## Misc

We should have a way to get the filed names of a record as `[string]`.
(Note: this is just the keys, not nested naming.)
This could be `fields()`.

`has()` should be a boolean operator on a record that says whether a record
has the given name (and it can be recursive with "." or with string array
like field.Static).  More generally, it can operate on an expression and
return true iff the expression is not equal to `error("missing")`.
Perhaps `missing` could be a reserved word like `null` that is the
same as `error("missing")`.

`is()` could be shorthand for a type boolean, e.g., `id.is(socket)`
where once we have constants you could put a definition for `conn`
in the Z:
```
let port = uint16
let socket = {orig_h:ip,orig_p:port,resp_h:ip,resp_p:port}
* | put hasSocket=id.is(socket)
```

We should have methods for all of this so we could say `.is(string)`
or `foo.is(string)` where we node this is not module naming.
If we ever do module naming we would might use something like `$` or `@`
to clarify the module reference.  Maybe we can get away without having this?

A sub-search can be easily integrated into the generator model by having
a sub-search simply be a generator of records.  Woohoo!  This is sweet.
```
put c=collect(search(<expr>).filter(<expr>))
```

## Matrix of `<agg>(<gen>), <running-agg>(<expr>), <predicate-agg>(<gen>)`

In search context, "or" collides with logical-or, but we could have a
generic "agg" function like this...
```
agg(or, select(*).map($=foo))
```

In expression context, the syntax-collision here is resolved because we don't
have and-concatentation so the parser can handle this:
```
... | put x = or(select(foo)) or or(select(bar)) | ...
```

Actually... if generators are syntatically distinct, then `or(<gen>)` can be
differentiated from `or (<expr>)`.

## @ operator

An operator is applied to a generator using BinaryExpr with operator `@`
(i.e,. this is what appears in the binary expression ast node).
We could have this in the Z language but we know when a generator is on
the left-hand side so we can overload "." and it will look cleaner.

With @-notation,
```
or(select(.).map($=foo))
```
would look like this:
```
or(.select(*)@map($=foo))
```

## TO DO

* `1+1=foo` not right yet... this should apply in expression context too so
things are the same.
* `cut(x).y=z` ... should `z` be a string here?  or identifier?
* `filter true` does a search for bool(true)... maybe true/false should be treated
special.  also, true shouldn't be an identifier unless escaped (like or etc)
* we need to test generators inside of generators, e.g., `collect(select(.).map(collect(select($.foo))`.  This should "just work" but
we should play with this further and see where we might want to take this.

> XXX for now just return (nil, nil) if it doesn't work...
> we should distinguish between "this is clearly a generator
> but there's an error" and this is something else...
> or maybe it's okay that the layer above flags the error.
> or maybe not because it will say "unknown function" when
> the function name might be right but the syntax here is wrong.
> we need an isAggregator test on the name then code to do
> either an continuous-agg or a generator-agg

## Discussion points

### `foo(bar)`

If you want `foo AND bar` should we required the `AND` or a space?
Or something else?

### Canonical Syntax

What did the compiler do?  Can look at AST but it would be nice to have
a clear and unambiguous canonical form so we could show the user
"this is what we think you want".  Noah had some thoughts on this based on
a few ideas from kusto.


### deprecating =~

We got rid of `=~`, which in other systems means case insensitive equality but
in our system was a hybrid.  It meant RE match and subnet match.  Previously,
`s=foo*` meant a literal match of `foo*` but `foo*` meant a glob keyword search.

With better glob handling, `s=foo*` should be a glob match
and `s="foo*"` should be literal match and s=/foo.*/ should
be regexp match.

Since we took out `=~`, I made this work
```
addr in 192.168.0.0/16
```

Also, it seems like this should work (cidr match over an array of nets)...
```
addr in [192.168.1.0/24, 192.168.2.0/24, 10.1.0.0/16]
```
but this means is the IP address one of the elements in the array.
The right way to do this (see below) is as follows:
```
or(select([192.168.1.0/24, 192.168.2.0/24, 10.1.0.0/16]).map(addr in $))
```

> Note: array expressions are not yet implemented nor is selection on
> an array expression but this is pretty straightforward and will come soon.

## Syntactic sugar

For example...
```
ANY departure IN schedule SATISFIES departure.utc > "23:41"
```
Here, `departure` is essentially the loop variable that takes on each
value in schedule and `ANY` performs a short-circuit OR of the predicate
give by `SATISFIES`.

This is really a lamba that is applied to a value then the results of
the lamba are operated upon.  Here, the lambda is boolean-valued:
```
lambda(x): x > "23:41"
```
and the logical operator is like the current `or` aggregator that is applied
to the sequence generated by the collection, e.g.,
```
vk over schedule: apply OR lambda(vk)
```

Given this, we could have low-level syntax that creates and applies lambdas
either as an aggregator or as a map function, let's call them `agg` and `apply`.
Then
