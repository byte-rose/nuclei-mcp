package main

import (
	"fmt"
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// The main function is now trialMain to avoid conflicts
func trialMain() {
	fmt.Println("Starting Nuclei examples...")

	// Basic example
	runBasicExample()

	// Advanced example with concurrency
	runAdvancedExample()

	fmt.Println("Completed Nuclei examples.")
}

func runBasicExample() {
	fmt.Println("Running basic Nuclei example...")

	// Create nuclei engine with options
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Severity: "critical"}), // Run critical severity templates only
	)
	if err != nil {
		panic(err)
	}

	// Load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"scanme.sh"}, false)

	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		fmt.Printf("Got result: %s\n", event.Info.Name)
	})
	if err != nil {
		panic(err)
	}

	// Close the engine when done
	defer ne.Close()

	fmt.Println("Basic example completed.")
}

func runAdvancedExample() {
	fmt.Println("Running advanced Nuclei example with concurrency...")

	// Create thread-safe nuclei engine for concurrent usage
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	if err != nil {
		panic(err)
	}
	defer ne.Close()

	// Setup waitgroup to handle concurrency
	wg := &sync.WaitGroup{}

	// Scan 1: Run HTTP templates on scanme.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		opts := []nuclei.NucleiSDKOptions{
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "http"}),
		}
		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"}, opts...)
		if err != nil {
			fmt.Printf("Error in HTTP scan: %v\n", err)
		}
	}()

	// Scan 2: Run DNS templates on honey.scanme.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		opts := []nuclei.NucleiSDKOptions{
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}),
		}
		err = ne.ExecuteNucleiWithOpts([]string{"honey.scanme.sh"}, opts...)
		if err != nil {
			fmt.Printf("Error in DNS scan: %v\n", err)
		}
	}()

	// Wait for all scans to finish
	wg.Wait()

	fmt.Println("Advanced example completed.")
}
