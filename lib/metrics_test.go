package vegeta

import (
	"testing"
	"time"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	m := NewMetrics(Results{
		&Result{500, time.Unix(0, 0), 100 * time.Millisecond, 10, 30, "Internal server error", "GET"},
		&Result{200, time.Unix(1, 0), 20 * time.Millisecond, 20, 20, "", "GET"},
		&Result{200, time.Unix(2, 0), 30 * time.Millisecond, 30, 10, "", "POST"},
	})
	getOnly := m.ByMethod["GET"]

	for field, values := range map[string][]float64{
		"BytesIn.Mean":  []float64{m.BytesIn.Mean, 20.0},
		"BytesOut.Mean": []float64{m.BytesOut.Mean, 20.0},
		"Sucess":        []float64{m.Success, 0.6666666666666666},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: want: %f, got: %f", field, values[1], values[0])
		}
	}

	for field, values := range map[string][]float64{
		"BytesIn.Mean":  []float64{getOnly.BytesIn.Mean, 25.0},
		"BytesOut.Mean": []float64{getOnly.BytesOut.Mean, 15.0},
		"Sucess":        []float64{getOnly.Success, 0.50},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: want: %f, got: %f", field, values[1], values[0])
		}
	}

	for field, values := range map[string][]time.Duration{
		"Latencies.Max":  []time.Duration{m.Latencies.Max, 100 * time.Millisecond},
		"Latencies.Mean": []time.Duration{m.Latencies.Mean, 50 * time.Millisecond},
		"Latencies.P50":  []time.Duration{m.Latencies.P50, 20 * time.Millisecond},
		"Latencies.P95":  []time.Duration{m.Latencies.P95, 30 * time.Millisecond},
		"Latencies.P99":  []time.Duration{m.Latencies.P99, 30 * time.Millisecond},
		"Duration":       []time.Duration{m.Duration, 2 * time.Second},
		"Wait":           []time.Duration{m.Wait, 30 * time.Millisecond},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: want: %s, got: %s", field, values[1], values[0])
		}
	}

	for field, values := range map[string][]time.Duration{
		"Latencies.Max":  []time.Duration{getOnly.Latencies.Max, 100 * time.Millisecond},
		"Latencies.Mean": []time.Duration{getOnly.Latencies.Mean, 60 * time.Millisecond},
		"Latencies.P50":  []time.Duration{getOnly.Latencies.P50, 20 * time.Millisecond},
		"Latencies.P95":  []time.Duration{getOnly.Latencies.P95, 20 * time.Millisecond},
		"Latencies.P99":  []time.Duration{getOnly.Latencies.P99, 20 * time.Millisecond},
		"Duration":       []time.Duration{getOnly.Duration, 1 * time.Second},
		"Wait":           []time.Duration{getOnly.Wait, 20 * time.Millisecond},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: want: %s, got: %s", field, values[1], values[0])
		}
	}

	for field, values := range map[string][]uint64{
		"BytesOut.Total": []uint64{m.BytesOut.Total, 60},
		"BytesIn.Total":  []uint64{m.BytesIn.Total, 60},
		"Requests":       []uint64{m.Requests, 3},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: want: %d, got: %d", field, values[1], values[0])
		}
	}

	for field, values := range map[string][]uint64{
		"BytesOut.Total": []uint64{getOnly.BytesOut.Total, 30},
		"BytesIn.Total":  []uint64{getOnly.BytesIn.Total, 50},
		"Requests":       []uint64{getOnly.Requests, 2},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: want: %d, got: %d", field, values[1], values[0])
		}
	}

	if len(m.StatusCodes) != 2 || m.StatusCodes["200"] != 2 || m.StatusCodes["500"] != 1 {
		t.Errorf("StatusCodes: want: %v, got: %v", map[int]int{200: 2, 500: 1}, m.StatusCodes)
	}

	if len(getOnly.StatusCodes) != 2 || getOnly.StatusCodes["200"] != 1 || getOnly.StatusCodes["500"] != 1 {
		t.Errorf("StatusCodes: want: %v, got: %v", map[int]int{200: 1, 500: 1}, getOnly.StatusCodes)
	}

	err := "Internal server error"
	if len(m.Errors) != 1 || m.Errors[0] != err {
		t.Errorf("Errors: want: %v, got: %v", []string{err}, m.Errors)
	}

	if len(getOnly.Errors) != 1 || getOnly.Errors[0] != err {
		t.Errorf("Errors: want: %v, got: %v", []string{err}, getOnly.Errors)
	}
}

func TestNewMetricsEmptyResults(t *testing.T) {
	_ = NewMetrics(Results{}) // Must not panic
}
