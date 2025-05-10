// Package osquery provides a query builder for OpenSearch.
package osquery

import (
	"testing"
)

func TestSortExtensions(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"sort with basic order only",
			Search().Sort(SortParams{Field: "field", Order: OrderAsc}),
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"field": map[string]interface{}{
							"order": "asc",
						},
					},
				},
			},
		},
		{
			"sort with mode",
			Search().Sort(SortParams{Field: "field", Order: OrderDesc, Mode: SortModeAvg}),
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"field": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"nested.field": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"nested.field": map[string]interface{}{
							"order":       "asc",
							"nested_path": "nested",
							"nested_filter": map[string]interface{}{
								"match": map[string]interface{}{
									"nested.type": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"nested.field": map[string]interface{}{
							"order":       "desc",
							"mode":        "max",
							"nested_path": "nested",
							"nested_filter": map[string]interface{}{
								"match": map[string]interface{}{
									"nested.type": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"field1": map[string]interface{}{
							"order": "asc",
						},
					},
					{
						"nested.field": map[string]interface{}{
							"order":       "desc",
							"mode":        "min",
							"nested_path": "nested",
							"nested_filter": map[string]interface{}{
								"match": map[string]interface{}{
									"nested.type": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"_script": map[string]interface{}{
							"type": "number",
							"script": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"_script": map[string]interface{}{
							"type": "number",
							"script": map[string]interface{}{
								"source": "doc['field_name'].value * params.factor",
								"lang":   "painless",
								"params": map[string]interface{}{
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
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"_score": map[string]interface{}{},
					},
					{
						"_script": map[string]interface{}{
							"type": "number",
							"script": map[string]interface{}{
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
				SortField(SortParams{Field: "regular_field", Order: OrderAsc}).
				SortByScript(
					Script("test_script").
						Source("doc['field_name'].value").
						Lang("painless"),
					"number",
					OrderDesc,
				),
			map[string]interface{}{
				"sort": []map[string]interface{}{
					{
						"regular_field": map[string]interface{}{
							"order": "asc",
						},
					},
					{
						"_script": map[string]interface{}{
							"type": "number",
							"script": map[string]interface{}{
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
