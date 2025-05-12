package osquery

import (
	"testing"
)

func TestFunctionScore(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"function_score query with random_score function",
			FunctionScore(Term("user", "kimchy")).
				Function(RandomScore()),
			map[string]interface{}{
				"function_score": map[string]interface{}{
					"query": map[string]interface{}{
						"term": map[string]interface{}{
							"user": map[string]interface{}{
								"value": "kimchy",
							},
						},
					},
					"functions": []map[string]interface{}{
						{
							"random_score": map[string]interface{}{},
						},
					},
				},
			},
		},
		{
			"function_score query with random_score function and boost_mode",
			FunctionScore(Term("user", "kimchy")).
				Function(RandomScore()).
				BoostMode("sum"),
			map[string]interface{}{
				"function_score": map[string]interface{}{
					"query": map[string]interface{}{
						"term": map[string]interface{}{
							"user": map[string]interface{}{
								"value": "kimchy",
							},
						},
					},
					"functions": []map[string]interface{}{
						{
							"random_score": map[string]interface{}{},
						},
					},
					"boost_mode": "sum",
				},
			},
		},
		{
			"function_score query with random_score function with seed",
			FunctionScore(Term("user", "kimchy")).
				Function(RandomScore().Seed(42)),
			map[string]interface{}{
				"function_score": map[string]interface{}{
					"query": map[string]interface{}{
						"term": map[string]interface{}{
							"user": map[string]interface{}{
								"value": "kimchy",
							},
						},
					},
					"functions": []map[string]interface{}{
						{
							"random_score": map[string]interface{}{
								"seed": int64(42),
							},
						},
					},
				},
			},
		},
		{
			"function_score query with random_score function with field",
			FunctionScore(Term("user", "kimchy")).
				Function(RandomScore().Field("_seq_no")),
			map[string]interface{}{
				"function_score": map[string]interface{}{
					"query": map[string]interface{}{
						"term": map[string]interface{}{
							"user": map[string]interface{}{
								"value": "kimchy",
							},
						},
					},
					"functions": []map[string]interface{}{
						{
							"random_score": map[string]interface{}{
								"field": "_seq_no",
							},
						},
					},
				},
			},
		},
		{
			"function_score query with multiple functions",
			FunctionScore(Term("user", "kimchy")).
				Function(RandomScore()).
				Function(RandomScore().Seed(123)),
			map[string]interface{}{
				"function_score": map[string]interface{}{
					"query": map[string]interface{}{
						"term": map[string]interface{}{
							"user": map[string]interface{}{
								"value": "kimchy",
							},
						},
					},
					"functions": []map[string]interface{}{
						{
							"random_score": map[string]interface{}{},
						},
						{
							"random_score": map[string]interface{}{
								"seed": int64(123),
							},
						},
					},
				},
			},
		},
		{
			"function_score query with match_all query",
			FunctionScore(MatchAll()).
				Function(RandomScore()),
			map[string]interface{}{
				"function_score": map[string]interface{}{
					"query": map[string]interface{}{
						"match_all": map[string]interface{}{},
					},
					"functions": []map[string]interface{}{
						{
							"random_score": map[string]interface{}{},
						},
					},
				},
			},
		},
	})
}

func TestFunctionScoreWithQuery(t *testing.T) {
	runMapTests(t, []mapTest{
		{
			"query with function_score",
			Query(
				FunctionScore(Term("user", "kimchy")).
					Function(RandomScore()).
					BoostMode("sum"),
			),
			map[string]interface{}{
				"query": map[string]interface{}{
					"function_score": map[string]interface{}{
						"query": map[string]interface{}{
							"term": map[string]interface{}{
								"user": map[string]interface{}{
									"value": "kimchy",
								},
							},
						},
						"functions": []map[string]interface{}{
							{
								"random_score": map[string]interface{}{},
							},
						},
						"boost_mode": "sum",
					},
				},
			},
		},
	})
}
