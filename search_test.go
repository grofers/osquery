// Modified by DefenseStation on 2024-06-06
// Changes: Updated ElasticSearch client to OpenSearch client, changed package name to 'osquery',
// updated references to OpenSearch documentation, and modified examples accordingly.

package osquery

import (
	"testing"
	"time"
)

func TestSearchMaps(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"a simple query with search after",
			Search().SearchAfter("_id", "name"),
			map[string]interface{}{
				"search_after": []string{"_id", "name"},
			},
		},
		{
			"a simple match_all query with a size and no aggs",
			Search().Query(MatchAll()).Size(20),
			map[string]interface{}{
				"query": map[string]interface{}{
					"match_all": map[string]interface{}{},
				},
				"size": 20,
			},
		},
		{
			"a complex query with an aggregation and various other options",
			Search().
				Query(
					Bool().
						Must(
							Range("date").
								Gt("some time in the past").
								Lte("now").
								Relation(RangeContains).
								TimeZone("Asia/Jerusalem").
								Boost(2.3),

							Match("author").
								Query("some guy").
								Analyzer("analyzer?").
								Fuzziness("fuzz"),
						).
						Boost(3.1),
				).
				Aggs(
					Sum("total_score", "score"),
					StringStats("tag_stats", "tags").
						ShowDistribution(true),
				).
				PostFilter(Range("score").Gt(0)).
				Size(30).
				From(5).
				Explain(true).
				Sort(
					FieldSort("field_1").Order(OrderDesc),
					FieldSort("field_2").Order(OrderAsc),
				).
				SourceIncludes("field_1", "field_2").
				SourceExcludes("field_3").
				Timeout(time.Duration(20000000000)).
				ScriptFields(
					Script("distance").
						Source("doc['coordinates'].arcDistance(params.lat,params.lon)").
						Params(ScriptParams{"lat": 48.8566, "lon": 2.3522}),
					Script("duration").
						ID("duration").
						Lang("painless"),
				),
			map[string]interface{}{
				"query": map[string]interface{}{
					"bool": map[string]interface{}{
						"must": []map[string]interface{}{
							{
								"range": map[string]interface{}{
									"date": map[string]interface{}{
										"gt":        "some time in the past",
										"lte":       "now",
										"relation":  "CONTAINS",
										"time_zone": "Asia/Jerusalem",
										"boost":     2.3,
									},
								},
							},
							{
								"match": map[string]interface{}{
									"author": map[string]interface{}{
										"query":     "some guy",
										"analyzer":  "analyzer?",
										"fuzziness": "fuzz",
									},
								},
							},
						},
						"boost": 3.1,
					},
				},
				"aggs": map[string]interface{}{
					"total_score": map[string]interface{}{
						"sum": map[string]interface{}{
							"field": "score",
						},
					},
					"tag_stats": map[string]interface{}{
						"string_stats": map[string]interface{}{
							"field":             "tags",
							"show_distribution": true,
						},
					},
				},
				"post_filter": map[string]interface{}{
					"range": map[string]interface{}{
						"score": map[string]interface{}{
							"gt": 0,
						},
					},
				},
				"size":    30,
				"from":    5,
				"explain": true,
				"timeout": "20s",
				"sort": []map[string]interface{}{
					{"field_1": map[string]interface{}{"order": "desc"}},
					{"field_2": map[string]interface{}{"order": "asc"}},
				},
				"_source": map[string]interface{}{
					"includes": []string{"field_1", "field_2"},
					"excludes": []string{"field_3"},
				},
				"script_fields": map[string]interface{}{
					"distance": map[string]interface{}{
						"script": map[string]interface{}{
							"source": "doc['coordinates'].arcDistance(params.lat,params.lon)",
							"params": map[string]interface{}{
								"lat": 48.8566,
								"lon": 2.3522,
							},
						},
					},
					"duration": map[string]interface{}{
						"script": map[string]interface{}{
							"id":   "duration",
							"lang": "painless",
						},
					},
				},
			},
		},
	})
}
