// Modified by DefenseStation on 2024-06-06
// Changes: Updated ElasticSearch client to OpenSearch client, changed package name to 'osquery',
// updated references to OpenSearch documentation, and modified examples accordingly.

package osquery

import (
	"github.com/fatih/structs"
)

type MultiMatchQuery struct {
	params multiMatchParams
}

// Map returns a map representation of the query; implementing the
// Mappable interface.
func (q *MultiMatchQuery) Map() map[string]interface{} {
	return map[string]interface{}{
		"multi_match": structs.Map(q.params),
	}
}

type multiMatchParams struct {
	Qry                 interface{}    `structs:"query"`
	Fields              []string       `structs:"fields"`
	Type                MultiMatchType `structs:"type,string,omitempty"`
	TieBrk              float32        `structs:"tie_breaker,omitempty"`
	Boost               float32        `structs:"boost,omitempty"`
	Anl                 string         `structs:"analyzer,omitempty"`
	AutoGenerate        *bool          `structs:"auto_generate_synonyms_phrase_query,omitempty"`
	Fuzz                string         `structs:"fuzziness,omitempty"`
	MaxExp              uint16         `structs:"max_expansions,omitempty"`
	PrefLen             uint16         `structs:"prefix_length,omitempty"`
	FuzzyTranspositions *bool          `structs:"fuzzy_transpositions,omitempty"`
	FuzzyRw             string         `structs:"fuzzy_rewrite,omitempty"`
	Lent                *bool          `structs:"lenient,omitempty"`
	Op                  MatchOperator  `structs:"operator,string,omitempty"`
	MinMatch            string         `structs:"minimum_should_match,omitempty"`
	ZeroTerms           ZeroTerms      `structs:"zero_terms_query,string,omitempty"`
	Slp                 uint16         `structs:"slop,omitempty"`
	Name                string         `structs:"_name,omitempty"`
}

// MultiMatch creates a new query of type "multi_match"
func MultiMatch(simpleQuery ...interface{}) *MultiMatchQuery {
	return newMultiMatch(simpleQuery...)
}

func newMultiMatch(simpleQuery ...interface{}) *MultiMatchQuery {
	var qry interface{}
	if len(simpleQuery) > 0 {
		qry = simpleQuery[len(simpleQuery)-1]
	}

	return &MultiMatchQuery{
		params: multiMatchParams{
			Qry: qry,
		},
	}
}

// Query sets the data to find in the query's field (it is the "query" component
// of the query).
func (q *MultiMatchQuery) Query(data interface{}) *MultiMatchQuery {
	q.params.Qry = data
	return q
}

// Name sets the name of the query that is returned in matched_queries in response
// if document matches the query.
func (q *MultiMatchQuery) Name(n string) *MultiMatchQuery {
	q.params.Name = n
	return q
}

// Analyzer sets the analyzer used to convert the text in the "query" value into
// tokens.
func (q *MultiMatchQuery) Analyzer(a string) *MultiMatchQuery {
	q.params.Anl = a
	return q
}

// Fields sets the fields used in the query
func (q *MultiMatchQuery) Fields(a ...string) *MultiMatchQuery {
	q.params.Fields = append(q.params.Fields, a...)
	return q
}

// AutoGenerateSynonymsPhraseQuery sets the "auto_generate_synonyms_phrase_query"
// boolean.
func (q *MultiMatchQuery) AutoGenerateSynonymsPhraseQuery(b bool) *MultiMatchQuery {
	q.params.AutoGenerate = &b
	return q
}

// Fuzziness set the maximum edit distance allowed for matching.
func (q *MultiMatchQuery) Fuzziness(f string) *MultiMatchQuery {
	q.params.Fuzz = f
	return q
}

// MaxExpansions sets the maximum number of terms to which the query will expand.
func (q *MultiMatchQuery) MaxExpansions(e uint16) *MultiMatchQuery {
	q.params.MaxExp = e
	return q
}

// PrefixLength sets the number of beginning characters left unchanged for fuzzy
// matching.
func (q *MultiMatchQuery) PrefixLength(l uint16) *MultiMatchQuery {
	q.params.PrefLen = l
	return q
}

// TieBreaker sets the tie breaker value
func (q *MultiMatchQuery) TieBreaker(l float32) *MultiMatchQuery {
	q.params.TieBrk = l
	return q
}

// Boost sets the boost value for the query.
func (q *MultiMatchQuery) Boost(l float32) *MultiMatchQuery {
	q.params.Boost = l
	return q
}

// FuzzyTranspositions sets whether edits for fuzzy matching include transpositions
// of two adjacent characters.
func (q *MultiMatchQuery) FuzzyTranspositions(b bool) *MultiMatchQuery {
	q.params.FuzzyTranspositions = &b
	return q
}

// FuzzyRewrite sets the method used to rewrite the query.
func (q *MultiMatchQuery) FuzzyRewrite(s string) *MultiMatchQuery {
	q.params.FuzzyRw = s
	return q
}

// Lenient sets whether format-based errors should be ignored.
func (q *MultiMatchQuery) Lenient(b bool) *MultiMatchQuery {
	q.params.Lent = &b
	return q
}

// Operator sets the boolean logic used to interpret text in the query value.
func (q *MultiMatchQuery) Operator(op MatchOperator) *MultiMatchQuery {
	q.params.Op = op
	return q
}

// Type sets the query type
func (q *MultiMatchQuery) Type(t MultiMatchType) *MultiMatchQuery {
	q.params.Type = t
	return q
}

// MinimumShouldMatch sets the minimum number of clauses that must match for a
// document to be returned.
func (q *MultiMatchQuery) MinimumShouldMatch(s string) *MultiMatchQuery {
	q.params.MinMatch = s
	return q
}

// Slop sets the maximum number of positions allowed between matching tokens.
func (q *MultiMatchQuery) Slop(n uint16) *MultiMatchQuery {
	q.params.Slp = n
	return q
}

// ZeroTermsQuery sets the "zero_terms_query" option to use. This indicates
// whether no documents are returned if the analyzer removes all tokens, such as
// when using a stop filter.
func (q *MultiMatchQuery) ZeroTermsQuery(s ZeroTerms) *MultiMatchQuery {
	q.params.ZeroTerms = s
	return q
}

// MultiMatchType is an enumeration type representing supported values for a
// multi match query's "type" parameter.
type MultiMatchType uint8

const (
	// MatchTypeBestFields is the "best_fields" type
	MatchTypeBestFields MultiMatchType = iota

	// MatchTypeMostFields is the "most_fields" type
	MatchTypeMostFields

	// MatchTypeCrossFields is the "cross_fields" type
	MatchTypeCrossFields

	// MatchTypePhrase is the "phrase" type
	MatchTypePhrase

	// MatchTypePhrasePrefix is the "phrase_prefix" type
	MatchTypePhrasePrefix

	// MatchTypeBoolPrefix is the "bool_prefix" type
	MatchTypeBoolPrefix
)

// String returns a string representation of the match operator, as known to
// OpenSearch.
func (a MultiMatchType) String() string {
	switch a {
	case MatchTypeBestFields:
		return "best_fields"
	case MatchTypeMostFields:
		return "most_fields"
	case MatchTypeCrossFields:
		return "cross_fields"
	case MatchTypePhrase:
		return "phrase"
	case MatchTypePhrasePrefix:
		return "phrase_prefix"
	case MatchTypeBoolPrefix:
		return "bool_prefix"
	default:
		return ""
	}
}
