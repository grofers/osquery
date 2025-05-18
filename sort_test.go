// Package osquery Modified by harshit98 on 2025-05-07
// Changes: Added sort params support like mode, nested_path, nested_filter
package osquery

import (
	"testing"
)

func TestSortExtensions(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"sort with basic order only",
			Search().Sort(SortParams{Field: "field", Order: OrderAsc}),
			map[string]any{
				"sort": []map[string]any{
					{
						"field": map[string]any{
							"order": "asc",
						},
					},
				},
			},
		},
		{
			"sort with mode",
			Search().Sort(SortParams{Field: "field", Order: OrderDesc, Mode: SortModeAvg}),
			map[string]any{
				"sort": []map[string]any{
					{
						"field": map[string]any{
							"order": "desc",
							"mode":  "avg",
						},
					},
				},
			},
		},
		{
			"sort with nested_path",
			Search().Sort(SortParams{Field: "nested.field", Order: OrderAsc, NestedPath: "nested"}),
			map[string]any{
				"sort": []map[string]any{
					{
						"nested.field": map[string]any{
							"order":       "asc",
							"nested_path": "nested",
						},
					},
				},
			},
		},
		{
			"sort with nested_path and nested_filter",
			Search().Sort(SortParams{
				Field:        "nested.field",
				Order:        OrderAsc,
				NestedPath:   "nested",
				NestedFilter: Match("nested.type").Query("value"),
			}),
			map[string]any{
				"sort": []map[string]any{
					{
						"nested.field": map[string]any{
							"order":       "asc",
							"nested_path": "nested",
							"nested_filter": map[string]any{
								"match": map[string]any{
									"nested.type": map[string]any{
										"query": "value",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			"sort with mode, nested_path and nested_filter",
			Search().Sort(SortParams{
				Field:        "nested.field",
				Order:        OrderDesc,
				Mode:         SortModeMax,
				NestedPath:   "nested",
				NestedFilter: Match("nested.type").Query("value"),
			}),
			map[string]any{
				"sort": []map[string]any{
					{
						"nested.field": map[string]any{
							"order":       "desc",
							"mode":        "max",
							"nested_path": "nested",
							"nested_filter": map[string]any{
								"match": map[string]any{
									"nested.type": map[string]any{
										"query": "value",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			"multiple sorts with different options",
			Search().
				Sort(SortParams{Field: "field1", Order: OrderAsc}).
				Sort(SortParams{
					Field:        "nested.field",
					Order:        OrderDesc,
					Mode:         SortModeMin,
					NestedPath:   "nested",
					NestedFilter: Match("nested.type").Query("value"),
				}),
			map[string]any{
				"sort": []map[string]any{
					{
						"field1": map[string]any{
							"order": "asc",
						},
					},
					{
						"nested.field": map[string]any{
							"order":       "desc",
							"mode":        "min",
							"nested_path": "nested",
							"nested_filter": map[string]any{
								"match": map[string]any{
									"nested.type": map[string]any{
										"query": "value",
									},
								},
							},
						},
					},
				},
			},
		},
	})
}

func TestScriptSortExtensions(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"sort with script",
			Search().SortByScript(
				Script("test_script").
					Source("doc['field_name'].value").
					Lang("painless"),
				"number",
				OrderDesc,
			),
			map[string]any{
				"sort": []map[string]any{
					{
						"_script": map[string]any{
							"type": "number",
							"script": map[string]any{
								"source": "doc['field_name'].value",
								"lang":   "painless",
							},
							"order": "desc",
						},
					},
				},
			},
		},
		{
			"sort with script and params",
			Search().SortByScript(
				Script("test_script").
					Source("doc['field_name'].value * params.factor").
					Lang("painless").
					Params(ScriptParams{"factor": 1.5}),
				"number",
				OrderAsc,
			),
			map[string]any{
				"sort": []map[string]any{
					{
						"_script": map[string]any{
							"type": "number",
							"script": map[string]any{
								"source": "doc['field_name'].value * params.factor",
								"lang":   "painless",
								"params": map[string]any{
									"factor": 1.5,
								},
							},
							"order": "asc",
						},
					},
				},
			},
		},
		{
			"sort with raw field and script",
			Search().
				SortRaw("_score").
				SortByScript(
					Script("test_script").
						Source("if (doc['parent_obj.score_field'].size()!=0) { return ( Math.log(doc['parent_obj.score_field'].value*100 + 10 ) * _score ) } else { return _score }").
						Lang("painless"),
					"number",
					OrderDesc,
				),
			map[string]any{
				"sort": []any{
					"_score",
					map[string]any{
						"_script": map[string]any{
							"type": "number",
							"script": map[string]any{
								"source": "if (doc['parent_obj.score_field'].size()!=0) { return ( Math.log(doc['parent_obj.score_field'].value*100 + 10 ) * _score ) } else { return _score }",
								"lang":   "painless",
							},
							"order": "desc",
						},
					},
				},
			},
		},
		{
			"mixed sort with field and script",
			Search().
				Sort(SortParams{Field: "regular_field", Order: OrderAsc}).
				SortByScript(
					Script("test_script").
						Source("doc['field_name'].value").
						Lang("painless"),
					"number",
					OrderDesc,
				),
			map[string]any{
				"sort": []map[string]any{
					{
						"regular_field": map[string]any{
							"order": "asc",
						},
					},
					{
						"_script": map[string]any{
							"type": "number",
							"script": map[string]any{
								"source": "doc['field_name'].value",
								"lang":   "painless",
							},
							"order": "desc",
						},
					},
				},
			},
		},
	})
}

// TestSortClear verifies the ClearSort functionality
func TestSortClear(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"clear sort removes all sort options",
			Search().
				Sort(SortParams{Field: "field1", Order: OrderAsc}).
				ClearSort(),
			map[string]any{
				// No "sort" key should be present when sort options are cleared
			},
		},
		{
			"add sort after clearing",
			Search().
				Sort(SortParams{Field: "field1", Order: OrderAsc}).
				ClearSort().
				Sort(SortParams{Field: "field2", Order: OrderDesc}),
			map[string]any{
				"sort": []map[string]any{
					{
						"field2": map[string]any{
							"order": "desc",
						},
					},
				},
			},
		},
		{
			"clear sort with no existing sort options",
			Search().ClearSort(),
			map[string]any{
				// No "sort" key should be present
			},
		},
		{
			"multiple sort operations with clear in between",
			Search().
				Sort(SortParams{Field: "field1", Order: OrderAsc}).
				Sort(SortParams{Field: "field2", Order: OrderDesc}).
				ClearSort().
				Sort(SortParams{Field: "field3", Order: OrderAsc}),
			map[string]any{
				"sort": []map[string]any{
					{
						"field3": map[string]any{
							"order": "asc",
						},
					},
				},
			},
		},
	})
}
