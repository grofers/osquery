// Package osquery Modified by harshit98 on 2025-05-10
// Changes: Added function score support
package osquery

type FunctionScoreQuery struct {
	query     Mappable
	functions []Function
	boostMode string
	scoreMode string
	maxBoost  float32
	minScore  float32
	boost     float32
}

type Function interface {
	Map() map[string]interface{}
}

type RandomScoreFunction struct {
	seed  *int64
	field string
}

type FieldValueFactorFunction struct {
	field    string
	factor   float32
	modifier string
	missing  float32
}

// Additional functions can be added as per usecase in future like:
// - ScriptScoreFunction
// - DecayFunction (with variants for geo, date, numeric)
// - WeightFunction
//
// For ref: https://docs.opensearch.org/docs/latest/query-dsl/compound/function-score/

func FunctionScore(query Mappable) *FunctionScoreQuery {
	return &FunctionScoreQuery{query: query}
}

func (q *FunctionScoreQuery) Function(f Function) *FunctionScoreQuery {
	q.functions = append(q.functions, f)
	return q
}

func (q *FunctionScoreQuery) BoostMode(mode string) *FunctionScoreQuery {
	q.boostMode = mode
	return q
}

func (q *FunctionScoreQuery) Map() map[string]interface{} {
	m := make(map[string]interface{})

	if q.query != nil {
		m["query"] = q.query.Map()
	}

	if len(q.functions) > 0 {
		funcs := make([]map[string]interface{}, len(q.functions))
		for i, f := range q.functions {
			funcs[i] = f.Map()
		}
		m["functions"] = funcs
	}

	if q.boostMode != "" {
		m["boost_mode"] = q.boostMode
	}

	return map[string]interface{}{
		"function_score": m,
	}
}

func RandomScore() *RandomScoreFunction {
	return &RandomScoreFunction{}
}

func (f *RandomScoreFunction) Seed(seed int64) *RandomScoreFunction {
	f.seed = &seed
	return f
}

func (f *RandomScoreFunction) Field(field string) *RandomScoreFunction {
	f.field = field
	return f
}

func (f *RandomScoreFunction) Map() map[string]interface{} {
	m := make(map[string]interface{})

	if f.seed != nil {
		m["seed"] = *f.seed
	}

	if f.field != "" {
		m["field"] = f.field
	}

	return map[string]interface{}{
		"random_score": m,
	}
}
