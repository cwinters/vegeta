package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	vegeta "github.com/tsenart/vegeta/lib"
)

func reportCmd() command {
	fs := flag.NewFlagSet("vegeta report", flag.ExitOnError)
	reporter := fs.String("reporter", "text", "Reporter [text, json, plot, hist[buckets]]")
	inputs := fs.String("inputs", "stdin", "Input files (comma separated, or glob)")
	output := fs.String("output", "stdout", "Output file")
	filters := fs.String("filters", "", "One or more space-separated filters to operate on subsets of the inputs")
	return command{fs, func(args []string) error {
		fs.Parse(args)
		return report(*reporter, *inputs, *output, *filters)
	}}
}

// report validates the report arguments, sets up the required resources
// and writes the report
func report(reporter, inputs, output, filters string) error {
	if len(reporter) < 4 {
		return fmt.Errorf("bad reporter: %s", reporter)
	}
	var rep vegeta.Reporter
	switch reporter[:4] {
	case "text":
		rep = vegeta.ReportText
	case "json":
		rep = vegeta.ReportJSON
	case "plot":
		rep = vegeta.ReportPlot
	case "hist":
		if len(reporter) < 6 {
			return fmt.Errorf("bad buckets: '%s'", reporter[4:])
		}
		var hist vegeta.HistogramReporter
		if err := hist.Set(reporter[4:len(reporter)]); err != nil {
			return err
		}
		rep = hist
	}

	fmt.Fprintf(os.Stderr, "CMW - Inputs received: %s\n", inputs)
	var (
		err   error
		files []string
	)
	if strings.Contains(inputs, "*") {
		if files, err = filepath.Glob(inputs); err != nil {
			panic(fmt.Sprintf("Bad glob %s: %s", inputs, err))
		}
	} else {
		files = strings.Split(inputs, ",")
	}
	srcs := make([]io.Reader, len(files))
	for i, f := range files {
		in, err := file(f, false)
		if err != nil {
			return err
		}
		defer in.Close()
		srcs[i] = in
	}
	out, err := file(output, true)
	if err != nil {
		return err
	}
	defer out.Close()

	var results vegeta.Results
	res, errs := vegeta.Collect(srcs...)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

outer:
	for {
		select {
		case _ = <-sig:
			break outer
		case r, ok := <-res:
			if !ok {
				break outer
			}
			results = append(results, r)
		case err, ok := <-errs:
			if !ok {
				break outer
			}
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "CMW Result count before: %d\n", len(results))
	results = filterResults(results, filters)
	fmt.Fprintf(os.Stderr, "CMW Result count after: %d\n", len(results))
	sort.Sort(results)
	data, err := rep.Report(results)
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	return err
}

func filterResults(results vegeta.Results, filters string) vegeta.Results {
	trimmed := strings.TrimSpace(filters)
	if trimmed == "" {
		return results
	}
	filterGroup := newFilterGroup(trimmed)
	var filtered vegeta.Results
	for _, result := range results {
		if filterGroup.Matches(result) {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

type ResultFilterGroup struct {
	filters []func(*vegeta.Result) bool
}

func newFilterGroup(filterSpecs string) ResultFilterGroup {
	group := ResultFilterGroup{}
	for _, filterSpec := range strings.Split(filterSpecs, " ") {
		pieces := strings.Split(filterSpec, "=")
		switch pieces[0] {
		case "Method":
			group.filters = append(group.filters, func(result *vegeta.Result) bool {
				return result.Method == pieces[1]
			})
		case "URL":
			group.filters = append(group.filters, func(result *vegeta.Result) bool {
				return strings.Contains(result.URL, pieces[1])
			})
		}
	}
	return group
}

func (g *ResultFilterGroup) Matches(result *vegeta.Result) bool {
	for _, filter := range g.filters {
		if !filter(result) {
			return false
		}
	}
	return true
}
