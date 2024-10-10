package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "sshmux",
		Usage: "sshpiperd sshmux plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "private-key",
				Usage:    "private key file used to connect to the target server",
				EnvVars:  []string{"SSHPIPERD_SSHMUX_PRIVATE_KEY"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "db",
				Usage:    "database file",
				EnvVars:  []string{"SSHPIPERD_SSHMUX_DB"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			plugin, err := newSshmuxPlugin(c.String("private-key"), c.String("db"))
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				NextAuthMethodsCallback: func(_ libplugin.ConnMetadata) ([]string, error) {
					return plugin.supportedMethods()
				},

				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					return plugin.findAndCreateUpstream(conn, string(password), nil)
				},

				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
					return plugin.findAndCreateUpstream(conn, "", key)
				},

				VerifyHostKeyCallback: func(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
					return plugin.verifyHostKey(conn, hostname, netaddr, key)
				},
			}, nil
		},
	})
}
