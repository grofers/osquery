package osquery

type Collapse struct {
	field string
	Mappable
}

func CollapseField(field string) Collapse {
	return Collapse{
		field: field,
	}
}

func (c Collapse) Map() map[string]interface{} {
	outerMap := make(map[string]interface{})
	if c.field != "" {
		outerMap = map[string]interface{}{
			"field": c.field,
		}
	}
	return outerMap
}
