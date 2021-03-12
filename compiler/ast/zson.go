package ast

type Value interface {
	valueNode()
}

const (
	ImpliedValueOp = "implied_value"
	CastValueOp    = "cast_value"
	DefValueOp     = "def_value"
)

type ImpliedValue struct {
	Op string `json:"op" unpack:""`
	Of Any    `json:"of"`
}

type DefValue struct {
	Op       string `json:"op" unpack:""`
	Of       Any    `json:"of"`
	TypeName string `json:"type_name"`
}

type CastValue struct {
	Op   string `json:"op" unpack:""`
	Of   Value  `json:"of"`
	Type Type   `json:"type"`
}

func (*ImpliedValue) valueNode() {}
func (*DefValue) valueNode()     {}
func (*CastValue) valueNode()    {}

type Any interface {
	anyNode()
}

type (
	Primitive struct {
		Op   string `json:"op" unpack:""`
		Type string `json:"type"`
		Text string `json:"text"`
	}
	Record struct {
		Op     string  `json:"op" unpack:""`
		Fields []Field `json:"fields"`
	}
	Field struct {
		Name  string `json:"name"`
		Value Value  `json:"value"`
	}
	Array struct {
		Op       string  `json:"op" unpack:""`
		Elements []Value `json:"elements"`
	}
	Set struct {
		Op       string  `json:"op" unpack:""`
		Elements []Value `json:"elements"`
	}
	Enum struct {
		Op   string `json:"op" unpack:""`
		Name string `json:"name"`
	}
	Map struct {
		Op      string  `json:"op" unpack:""`
		Entries []Entry `json:"entries"`
	}
	Entry struct {
		Key   Value `json:"key"`
		Value Value `json:"value"`
	}
	TypeValue struct {
		Op    string `json:"op" unpack:""`
		Value Type   `json:"value"`
	}
)

func (*Primitive) anyNode()  {}
func (*Record) anyNode()     {}
func (*Array) anyNode()      {}
func (*Set) anyNode()        {}
func (*Enum) anyNode()       {}
func (*Map) anyNode()        {}
func (*TypeValue) anyNode()  {}
func (*TypeValue) exprNode() {}

type Type interface {
	typeNode()
}

type (
	TypePrimitive struct {
		Op   string `json:"op" unpack:""`
		Name string `json:"name"`
	}
	TypeRecord struct {
		Op     string      `json:"op" unpack:""`
		Fields []TypeField `json:"fields"`
	}
	TypeField struct {
		Name string `json:"name"`
		Type Type   `json:"type"`
	}
	TypeArray struct {
		Op   string `json:"op" unpack:""`
		Type Type   `json:"type"`
	}
	TypeSet struct {
		Op   string `json:"op" unpack:""`
		Type Type   `json:"type"`
	}
	TypeUnion struct {
		Op    string `json:"op" unpack:""`
		Types []Type `json:"types"`
	}
	// Enum has just the elements and relies on the semantic checker
	// to determine a type from the decorator either within or from above.
	TypeEnum struct {
		Op       string  `json:"op" unpack:""`
		Elements []Field `json:"elements"`
	}
	TypeMap struct {
		Op      string `json:"op" unpack:""`
		KeyType Type   `json:"key_type"`
		ValType Type   `json:"val_type"`
	}
	TypeNull struct {
		Op string `json:"op" unpack:""`
	}
	TypeName struct {
		Op   string `json:"op" unpack:""`
		Name string `json:"name"`
	}
	TypeDef struct {
		Op   string `json:"op" unpack:""`
		Name string `json:"name"`
		Type Type   `json:"type"`
	}
)

func (*TypePrimitive) typeNode() {}
func (*TypeRecord) typeNode()    {}
func (*TypeArray) typeNode()     {}
func (*TypeSet) typeNode()       {}
func (*TypeUnion) typeNode()     {}
func (*TypeEnum) typeNode()      {}
func (*TypeMap) typeNode()       {}
func (*TypeNull) typeNode()      {}
func (*TypeName) typeNode()      {}
func (*TypeDef) typeNode()       {}
