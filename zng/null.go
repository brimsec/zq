package zng

import (
	"fmt"

	"github.com/brimsec/zq/zcode"
)

type TypeOfNull struct{}

func (t *TypeOfNull) Parse(in []byte) (zcode.Bytes, error) {
	if len(in) > 0 {
		return nil, fmt.Errorf("cannot instantiate type null with nonempty value %q", in)
	}
	return nil, nil
}

func (t *TypeOfNull) ID() int {
	return IdNull
}

func (t *TypeOfNull) String() string {
	return "null"
}

func (t *TypeOfNull) Marshal(zv zcode.Bytes) (interface{}, error) {
	return nil, nil
}

func (t *TypeOfNull) ZSON() string {
	return "null"
}

func (t *TypeOfNull) ZSONOf(zv zcode.Bytes) string {
	return "null"
}
