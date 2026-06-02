package main

import (
	"flag"
	"fmt"
	"os"

	"sni-spoofing-go/helper"
)

func runHelperMode() {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var listen, token, guiEvent string
	var parentPID int
	fs.StringVar(&listen, "listen", "", "TCP listen address")
	fs.StringVar(&token, "token", "", "auth token")
	fs.IntVar(&parentPID, "parent-pid", 0, "GUI process id to watch")
	fs.StringVar(&guiEvent, "gui-event", "", "named event held open by the GUI")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "helper flags:", err)
		os.Exit(2)
	}
	if listen == "" || token == "" {
		fmt.Fprintln(os.Stderr, "helper mode requires -listen ADDR and -token TOKEN")
		os.Exit(2)
	}
	helper.LogHelperStartup(listen, parentPID, guiEvent, os.Args)
	if err := helper.RunServer(listen, token, parentPID, guiEvent); err != nil {
		helper.LogHelperError("helper exit: %v", err)
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func isHelperMode(args []string) bool {
	for _, a := range args[1:] {
		if a == "-helper" {
			return true
		}
	}
	return false
}
