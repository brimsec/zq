package zng

// Column defines the field name and type of a column in a record type.
type Column struct {
	Name string
	Type Type
}

func NewColumn(name string, typ Type) Column {
	return Column{name, typ}
}
