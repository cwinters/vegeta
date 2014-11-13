package vegeta

import (
	"strconv"
	"time"

	"github.com/bmizerany/perks/quantile"
)

var Methods = []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS", "HEAD"}

// Metrics holds the stats computed out of a slice of Results
// that is used for some of the Reporters
type Metrics struct {
	Latencies struct {
		Mean time.Duration `json:"mean"`
		P50  time.Duration `json:"50th"` // P50 is the 50th percentile upper value
		P95  time.Duration `json:"95th"` // P95 is the 95th percentile upper value
		P99  time.Duration `json:"99th"` // P99 is the 99th percentile upper value
		Max  time.Duration `json:"max"`
	} `json:"latencies"`

	BytesIn struct {
		Total uint64  `json:"total"`
		Mean  float64 `json:"mean"`
	} `json:"bytes_in"`

	BytesOut struct {
		Total uint64  `json:"total"`
		Mean  float64 `json:"mean"`
	} `json:"bytes_out"`

	// Duration is the duration of the attack.
	Duration time.Duration `json:"duration"`
	// Wait is the extra time waiting for responses from targets.
	Wait time.Duration `json:"wait"`
	// Requests is the total number of requests executed.
	Requests uint64 `json:"requests"`
	// Success is the percentage of non-error responses.
	Success float64 `json:"success"`
	// StatusCodes is a histogram of the responses' status codes.
	StatusCodes map[string]int `json:"status_codes"`
	// Errors is a set of unique errors returned by the targets during the attack.
	Errors []string `json:"errors"`
	// ByMethod is this same group of metrics but for a subset of the requests
	ByMethod map[string]*Metrics `json:"metrics_by_method"`

	earliestResult    time.Time
	errorSet          map[string]struct{}
	latestResult      time.Time
	latestTotalResult time.Time
	quants            *quantile.Stream
	totalLatencies    time.Duration
	totalRequests     int
	totalSuccess      int
}

func (m *Metrics) AddResult(result *Result) {
	if m.totalRequests == 0 {
		m.earliestResult = result.Timestamp
	}
	m.totalRequests++
	m.StatusCodes[strconv.Itoa(int(result.Code))]++
	m.totalLatencies += result.Latency
	m.BytesOut.Total += result.BytesOut
	m.BytesIn.Total += result.BytesIn
	if result.Latency > m.Latencies.Max {
		m.Latencies.Max = result.Latency
	}
	if result.Timestamp.After(m.latestResult) {
		m.latestResult = result.Timestamp
	}
	if end := result.Timestamp.Add(result.Latency); end.After(m.latestTotalResult) {
		m.latestTotalResult = end
	}
	if result.Code >= 200 && result.Code < 300 {
		m.totalSuccess++
	}
	if result.Error != "" {
		m.errorSet[result.Error] = struct{}{}
	}
	m.quants.Insert(float64(result.Latency))
}

func (m *Metrics) Complete() {
	m.Requests = uint64(m.totalRequests)
	m.Duration = m.latestResult.Sub(m.earliestResult)
	m.Wait = m.latestTotalResult.Sub(m.latestResult)
	m.BytesIn.Mean = float64(m.BytesIn.Total) / float64(m.Requests)
	m.BytesOut.Mean = float64(m.BytesOut.Total) / float64(m.Requests)
	m.Success = float64(m.totalSuccess) / float64(m.Requests)

	m.Latencies.Mean = time.Duration(float64(m.totalLatencies) / float64(m.totalRequests))
	m.Latencies.P50 = time.Duration(m.quants.Query(0.50))
	m.Latencies.P95 = time.Duration(m.quants.Query(0.95))
	m.Latencies.P99 = time.Duration(m.quants.Query(0.99))

	m.Errors = make([]string, 0, len(m.errorSet))
	for err := range m.errorSet {
		m.Errors = append(m.Errors, err)
	}
	for _, metrics := range m.ByMethod {
		metrics.Complete()
	}
}

// NewMetrics computes and returns a Metrics struct out of a slice of Results.
func NewMetrics(r Results) *Metrics {
	m := &Metrics{
		StatusCodes: map[string]int{},
		ByMethod:    map[string]*Metrics{},
		errorSet:    map[string]struct{}{},
		quants:      quantile.NewTargeted(0.50, 0.95, 0.99),
	}
	for _, method := range Methods {
		m.ByMethod[method] = &Metrics{
			StatusCodes: map[string]int{},
			errorSet:    map[string]struct{}{},
			quants:      quantile.NewTargeted(0.50, 0.95, 0.99),
		}
	}

	if len(r) == 0 {
		return m
	}

	for _, result := range r {
		m.AddResult(result)
		m.ByMethod[result.Method].AddResult(result)
	}

	m.Complete()
	return m
}
