package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
	"github.com/cnfatal/subscription-converter/builtin"
)

const usage = `subscription-converter converts proxy client configurations.

Usage:
  subscription-converter convert [options]
  subscription-converter serve [options]
  subscription-converter formats
  subscription-converter version

Run "subscription-converter <command> -help" for command options.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return flag.ErrHelp
	}
	switch args[0] {
	case "convert":
		return runConvert(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout)
	case "formats":
		engine := builtin.New()
		fmt.Fprintf(stdout, "formats: %v\n", engine.Formats())
		return nil
	case "version":
		fmt.Fprintln(stdout, subscriptionconverter.GetVersion().String())
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runConvert(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("convert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	from := flags.String("from", "auto", "input format or auto")
	to := flags.String("to", "sing-box", "output format")
	input := flags.String("input", "-", "input file, HTTP(S) URL, or - for stdin")
	output := flags.String("output", "-", "output file or - for stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	data, err := subscriptionconverter.Load(*input)
	if err != nil {
		return err
	}
	result, err := builtin.New().ConvertWithOptions(data, subscriptionconverter.ConvertOptions{
		From: *from,
		To:   *to,
		Decode: subscriptionconverter.DecodeOptions{
			BaseDirectory: subscriptionconverter.SourceBaseDirectory(subscriptionconverter.ResolveSource(*input, ".")),
		},
	})
	for _, warning := range result.Warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	if err != nil {
		return err
	}
	if *output == "-" {
		_, err = stdout.Write(result.Content)
		return err
	}
	if err := os.WriteFile(*output, result.Content, 0o600); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func runServe(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "config.yaml", "server configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := subscriptionconverter.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	handler, err := subscriptionconverter.NewHandler(config, builtin.New(), logger)
	if err != nil {
		return err
	}
	logger.Info("server listening", "address", config.Server.Listen, "subscriptions", len(config.Subscriptions))
	err = subscriptionconverter.Listen(config.Server.Listen, handler.Routes())
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
