package sshpiperplugin

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sshmux/common"
	"strings"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

var errUserFormat = errors.New("invalid ssh user format")
var errTargetNotFound = errors.New("no matching target found")

type plugin struct {
	api        *common.API
	privateKey []byte
}

func (p *plugin) parseUserAndTarget(sshuser string) (string, *common.Target, error) {
	seps := strings.SplitN(sshuser, ":", 2)
	if len(seps) != 2 {
		return "", nil, errUserFormat
	}
	user := seps[0]
	targetName := seps[1]
	target := p.api.GetTargetByName(targetName)
	if target == nil {
		return "", nil, errTargetNotFound
	}
	return user, target, nil
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

	user, target, err := p.parseUserAndTarget(sshuser)

	if err != nil {
		return nil, err
	}

	pubkeys := p.api.GetPubkeysByUsername(user)
	for _, pubkey := range pubkeys {
		authedPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey.Key))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key [%v]", pubkey.Key)
		}
		if bytes.Equal(authedPubkey.Marshal(), publicKey) {
			pubkey.UsedAt = time.Now()
			p.api.PubkeyUsedAt(pubkey)
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

func (p *plugin) banner(conn libplugin.ConnMetadata) string {
	sshuser := conn.User()

	_, target, err := p.parseUserAndTarget(sshuser)

	if err != nil {
		if errors.Is(err, errUserFormat) {
			return "ssh user should be in the format of <username>:<target>.\n"
		} else if errors.Is(err, errTargetNotFound) {
			return "no matching target.\n"
		} else {
			return ""
		}
	}

	if !common.TestSSHConnection(*target) {
		return fmt.Sprintf("target %v is not reachable.\n", target.Name)
	}
	return ""
}

func (p *plugin) pipeEnd(conn libplugin.ConnMetadata, _ error) {
	sshuser := conn.User()

	username, target, err := p.parseUserAndTarget(sshuser)

	if err != nil {
		return
	}

	user := p.api.GetUserByName(username)

	if user == nil {
		return
	}

	recording := common.Recording{
		UserID:   user.ID,
		TargetID: target.ID,
		RecordID: conn.UniqueID(),
	}

	p.api.CreateRecording(recording)
}
