package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "repository root")
	jsonOutput := flag.Bool("json", false, "emit machine-readable summary")
	flag.Parse()
	summary, err := ValidateRepository(*root)
	if *jsonOutput {
		output := map[string]any{"valid": err == nil, "summary": summary}
		if err != nil {
			output["error"] = err.Error()
		}
		encoded, marshalErr := json.Marshal(output)
		if marshalErr != nil {
			fmt.Fprintln(os.Stderr, marshalErr)
			os.Exit(3)
		}
		fmt.Println(string(encoded))
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "support-check: INVALID")
		fmt.Fprintln(os.Stderr, err)
	} else {
		fmt.Printf("support-check: VALID candidate (%d cells, %d profiles, %d drivers, %d runtime adapters, %d external adapters; %d passed claims)\n",
			summary.Cells, summary.Profiles, summary.Drivers, summary.RuntimeAdapters, summary.ExternalAdapters, summary.PassedClaims)
	}
	if err != nil {
		os.Exit(2)
	}
}
