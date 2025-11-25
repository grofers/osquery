package osquery

import "testing"

func TestCollapse(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"Basic collapse testing",
			NewCollapse("variant_group.group_id"),
			map[string]interface{}{
				"field": "variant_group.group_id",
			},
		},
	})
}
