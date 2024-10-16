package sshpiperplugin

import (
	"sshmux/common"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func StartPlugin(cCtx *cli.Context) error {
	configPath := cCtx.String("config")
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return err
	}

	plugin, err := newSshmuxPlugin(config.PrivateKey, config.DB)
	if err != nil {
		return err
	}
	sshPiperPluginConfig := &libplugin.SshPiperPluginConfig{
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
		BannerCallback: plugin.banner,
	}

	p, err := libplugin.NewFromStdio(*sshPiperPluginConfig)
	if err != nil {
		return err
	}

	libplugin.ConfigStdioLogrus(p, nil, nil)
	return p.Serve()
}
