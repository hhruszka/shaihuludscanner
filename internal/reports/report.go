package reports

import (
	"fmt"
	"os"
	"shaihuludscanner/internal/yara"
	"text/tabwriter"
)

func GenerateReport(results []yara.Match, walkedDirs, walkedFiles, scannedFiles int) {
	fmt.Println()
	fmt.Printf("Walked %d dirs and %d files\n", walkedDirs, walkedFiles)
	fmt.Printf("Scanned %d files\n", scannedFiles)
	fmt.Println("Scan complete")

	if len(results) == 0 {
		fmt.Println()
		fmt.Println("No Shai Hulud IoCs found")
	}
	if len(results) > 0 {
		fmt.Println()
		fmt.Println("Shai Hulud IoCs found! System infected!")
		// Print results
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		_, _ = fmt.Fprintf(tw, "Rule\tPath\n")
		for _, match := range results {
			fmt.Fprintf(tw, "%s\t%s\n", match.Rule, match.FilePath)
		}
		tw.Flush()
	}
}
