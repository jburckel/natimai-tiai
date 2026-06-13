// Command tiai-agent is the Windows endpoint agent.
//
// Skeleton commands: run / version / init-config. Windows service install
// (golang.org/x/sys/windows/svc) and WMI Defender access are ported from
// natimai-windows-console in M1/M2.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tiai/agent/internal/agent"
	"tiai/agent/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		doRun(os.Args[2:])
	case "init-config":
		doInitConfig(os.Args[2:])
	case "version":
		fmt.Printf("Tiai agent v%s\n", agent.Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Tiai agent v" + agent.Version)
	fmt.Println()
	fmt.Println("Usage: tiai-agent <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run            Run the polling loop (foreground)")
	fmt.Println("  init-config    Generate a default config file")
	fmt.Println("  version        Show version")
	fmt.Println()
	fmt.Println("  TODO (M1): install/uninstall/start/stop as a Windows service.")
}

func doRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "config file path")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := agent.New(cfg, *cfgPath)
	fmt.Println("Agent running. Press Ctrl+C to stop.")
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		os.Exit(1)
	}
}

func doInitConfig(args []string) {
	fs := flag.NewFlagSet("init-config", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "config file path")
	apiURL := fs.String("api-url", "https://tiai.natimai.local", "API base URL")
	machineUUID := fs.String("machine-uuid", "", "optional identity override (else auto-resolved: SMBIOS UUID / agent UUID)")
	_ = fs.Parse(args)

	cfg := config.DefaultConfig()
	cfg.APIBaseURL = *apiURL
	cfg.MachineUUID = *machineUUID

	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Config written to %s\n", *cfgPath)
	fmt.Println("Set enrollment_secret and TLS as needed. Identity is auto-resolved at first run.")
}
