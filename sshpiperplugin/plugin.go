package sshpiperplugin

import (
	"bytes"
	"fmt"
	"os"
	"sshmux/common"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type plugin struct {
	api        *common.API
	privateKey []byte
}

func newSshmuxPlugin(privayeKeyFile string, dbPath string) (*plugin, error) {
	privateKey, err := os.ReadFile(privayeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file [%v]: %v", privayeKeyFile, err)
	}
	api, err := common.NewAPI(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create sshmux api: %v", err)
	}
	return &plugin{
		privateKey: privateKey,
		api:        api,
	}, nil
}

func (p *plugin) supportedMethods() ([]string, error) {
	var methods []string
	// only support publickey
	methods = append(methods, "publickey")
	return methods, nil
}

func (p *plugin) findAndCreateUpstream(conn libplugin.ConnMetadata, _ string, publicKey []byte) (*libplugin.Upstream, error) {
	sshuser := conn.User()

	seps := strings.SplitN(sshuser, ":", 2)
	if len(seps) != 2 {
		return nil, fmt.Errorf("invalid ssh user [%v]", sshuser)
	}
	user := seps[0]
	targetName := seps[1]
	log.Infof("user [%v] target [%v]", user, targetName)

	target := p.api.GetTargetByName(targetName)

	if target == nil {
		log.Warnf("no matching target for target name [%v] found", targetName)
		return nil, fmt.Errorf("no matching target for target name [%v] found", targetName)
	}

	pubkeys := p.api.GetPubkeysByUsername(user)
	for _, pubkey := range pubkeys {
		authedPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey.Key))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key [%v]", pubkey.Key)
		}
		if bytes.Equal(authedPubkey.Marshal(), publicKey) {
			return &libplugin.Upstream{
				Host:          target.Host,
				Port:          target.Port,
				IgnoreHostKey: true,
				UserName:      target.User,
				Auth:          libplugin.CreatePrivateKeyAuth(p.privateKey),
			}, nil
		}
	}

	return nil, fmt.Errorf("no matching public key found for user [%v]", user)
}

func (p *plugin) verifyHostKey(_ libplugin.ConnMetadata, _, _ string, _ []byte) error {
	// trust all host key
	return nil
}
