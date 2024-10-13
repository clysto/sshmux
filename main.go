package main

import (
	"fmt"
	"os"
	"sshmux/cmd"
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
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "toml config file",
				DefaultText: "/etc/sshmux.toml",
				Required:    true,
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
			{
				Name:      "passwd",
				Usage:     "change user password",
				Args:      true,
				ArgsUsage: "<username> <password>",
				Action:    cmd.Passwd,
			},
			{
				Name:      "admin",
				Usage:     "set user as admin",
				Args:      true,
				ArgsUsage: "<username> <true|false>",
				Action:    cmd.SetAdmin,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}
