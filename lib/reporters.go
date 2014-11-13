package vegeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"text/tabwriter"
)

// Reporter is an interface defining Report computation.
type Reporter interface {
	Report(Results) ([]byte, error)
}

// ReporterFunc is an adapter to allow the use of ordinary functions as
// Reporters. If f is a function with the appropriate signature, ReporterFunc(f)
// is a Reporter object that calls f.
type ReporterFunc func(Results) ([]byte, error)

// Report implements the Reporter interface.
func (f ReporterFunc) Report(r Results) ([]byte, error) { return f(r) }

// ReportText returns a computed Metrics struct as aligned, formatted text.
var ReportText ReporterFunc = func(r Results) ([]byte, error) {
	allMetrics := NewMetrics(r)
	out := &bytes.Buffer{}

	w := tabwriter.NewWriter(out, 0, 8, 2, '\t', tabwriter.StripEscape)
	metricsToText(allMetrics, w, "ALL")
	for method, methodMetrics := range allMetrics.ByMethod {
		metricsToText(methodMetrics, w, method)
	}
	if err := w.Flush(); err != nil {
		return []byte{}, err
	}
	return out.Bytes(), nil
}

func metricsToText(m *Metrics, w *tabwriter.Writer, label string) {
	latencyLabels := "[mean, 50, 95, 99, max]"
	fmt.Fprintf(w, "Requests (%s)\t[total]\t%d\n", label, m.Requests)
	fmt.Fprintf(w, "Duration (%s)\t[total, attack, wait]\t%s, %s, %s\n", label, m.Duration+m.Wait, m.Duration, m.Wait)
	fmt.Fprintf(w, "Latencies (%s)\t%s\t%s, %s, %s, %s, %s\n",
		label, latencyLabels, m.Latencies.Mean, m.Latencies.P50, m.Latencies.P95, m.Latencies.P99, m.Latencies.Max)
	fmt.Fprintf(w, "Bytes In (%s)\t[total, mean]\t%d, %.2f\n", label, m.BytesIn.Total, m.BytesIn.Mean)
	fmt.Fprintf(w, "Bytes Out (%s)\t[total, mean]\t%d, %.2f\n", label, m.BytesOut.Total, m.BytesOut.Mean)
	fmt.Fprintf(w, "Success (%s)\t[ratio]\t%.2f%%\n", label, m.Success*100)
	fmt.Fprintf(w, "Status Codes (%s)\t[code:count]\t", label)
	for code, count := range m.StatusCodes {
		fmt.Fprintf(w, "%s:%d  ", code, count)
	}
	fmt.Fprintln(w, "\nError Set:")
	for _, err := range m.Errors {
		fmt.Fprintln(w, err)
	}

}

// ReportJSON writes a computed Metrics struct to as JSON
var ReportJSON ReporterFunc = func(r Results) ([]byte, error) {
	return json.Marshal(NewMetrics(r))
}

// ReportPlot builds up a self contained HTML page with an interactive plot
// of the latencies of the requests. Built with http://dygraphs.com/
var ReportPlot ReporterFunc = func(r Results) ([]byte, error) {
	series := &bytes.Buffer{}
	for i, point := 0, ""; i < len(r); i++ {
		point = "[" + strconv.FormatFloat(
			r[i].Timestamp.Sub(r[0].Timestamp).Seconds(), 'f', -1, 32) + ","

		if r[i].Error == "" {
			point += "NaN," + strconv.FormatFloat(r[i].Latency.Seconds()*1000, 'f', -1, 32) + "],"
		} else {
			point += strconv.FormatFloat(r[i].Latency.Seconds()*1000, 'f', -1, 32) + ",NaN],"
		}

		series.WriteString(point)
	}
	// Remove trailing commas
	if series.Len() > 0 {
		series.Truncate(series.Len() - 1)
	}

	return []byte(fmt.Sprintf(plotsTemplate, dygraphJSLibSrc(), series)), nil
}

const plotsTemplate = `<!doctype>
<html>
<head>
  <title>Vegeta Plots</title>
</head>
<body>
  <div id="latencies" style="font-family: Courier; width: 100%%; height: 600px"></div>
  <a href="#" download="vegetaplot.png" onclick="this.href = document.getElementsByTagName('canvas')[0].toDataURL('image/png').replace(/^data:image\/[^;]/, 'data:application/octet-stream')">Download as PNG</a>
  <script>
	%s
  </script>
  <script>
  new Dygraph(
    document.getElementById("latencies"),
    [%s],
    {
      title: 'Vegeta Plot',
      labels: ['Seconds', 'ERR', 'OK'],
      ylabel: 'Latency (ms)',
      xlabel: 'Seconds elapsed',
      showRoller: true,
      colors: ['#FA7878', '#8AE234'],
      legend: 'always',
      logscale: true,
      strokeWidth: 1.3
    }
  );
  </script>
</body>
</html>`
