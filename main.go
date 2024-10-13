package main

import (
	"fmt"
	"os"
	"sshmux/http"
	"sshmux/sshpiperplugin"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:      "sshmux",
		Usage:     "sshmux",
		Writer:    os.Stderr,
		ErrWriter: os.Stderr,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Aliases:  []string{"c"},
				Usage:    "toml config file",
				Required: true,
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "serve",
				Usage:  "start manage web server",
				Action: http.RunServer,
			},
			{
				Name:   "plugin",
				Usage:  "start sshpiper plugin",
				Action: sshpiperplugin.StartPlugin,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}
