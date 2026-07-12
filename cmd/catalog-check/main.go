package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/whyiug/agentapi-doctor/internal/catalog"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "strictly validate generated artifacts and require zero diff")
	write := flag.Bool("write", false, "regenerate deterministic candidate artifacts")
	flag.Parse()
	if *check == *write {
		fmt.Fprintln(os.Stderr, "exactly one of --check or --write is required")
		os.Exit(2)
	}
	var (
		statistics *catalog.CatalogStatistics
		err        error
	)
	if *write {
		statistics, err = catalog.WriteGenerated(*root)
	} else {
		statistics, err = catalog.Check(*root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalog-check:", err)
		os.Exit(1)
	}
	fmt.Printf("catalog-check: ok mode=%s scenarios=%d denominator=%s status=%s/%s\n",
		map[bool]string{true: "write", false: "check"}[*write], statistics.ScenarioCount,
		statistics.DenominatorDigest, statistics.Status, statistics.ReviewStatus)
}
