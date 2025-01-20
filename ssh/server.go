package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"sshmux/common"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var errUserFormat = errors.New("invalid ssh user format")
var errTargetNotFound = errors.New("no matching target found")

type challengeContext struct {
	Username string
	Target   *common.Target
	UniqID   string
}

func (c *challengeContext) Meta() interface{} {
	return c
}

func (c *challengeContext) ChallengedUsername() string {
	return c.Username
}

type SSHServer struct {
	hostKey    []byte
	privateKey ssh.Signer
	port       int
	host       string
	config     *ssh.PiperConfig
	listener   net.Listener
	api        *common.API
	recorddir  string
}

func (s *SSHServer) Start() error {
	s.config = &ssh.PiperConfig{
		CreateChallengeContext: s.createChallengeContext,
		NextAuthMethods:        s.supportedMethods,
		PublicKeyCallback:      s.findAndCreateUpstream,
		BannerCallback:         s.banner,
	}
	private, err := ssh.ParsePrivateKey(s.hostKey)
	if err != nil {
		return err
	}
	s.config.AddHostKey(private)

	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))

	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Infof("ssh server listening on %s\n", addr)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Debugf("failed to accept connection: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SSHServer) handleConnection(conn net.Conn) {
	log.Infof("connection accepted: %v", conn.RemoteAddr())
	defer conn.Close()

	pipec := make(chan *ssh.PiperConn)
	errorc := make(chan error)

	go func() {
		p, err := ssh.NewSSHPiperConn(conn, s.config)

		if err != nil {
			errorc <- err
			return
		}

		pipec <- p
	}()

	var p *ssh.PiperConn
	select {
	case p = <-pipec:
	case err := <-errorc:
		log.Debugf("connection from %v establishing failed reason: %v", conn.RemoteAddr(), err)
		return
	case <-time.After(time.Second * 5):
		log.Debugf("pipe establishing timeout, disconnected connection from %v", conn.RemoteAddr())
		return
	}
	defer p.Close()

	log.Infof("ssh connection pipe created %v (username [%v]) -> %v (username [%v])", p.DownstreamConnMeta().RemoteAddr(), p.DownstreamConnMeta().User(), p.UpstreamConnMeta().RemoteAddr(), p.UpstreamConnMeta().User())

	var uphook func([]byte) ([]byte, error)
	var downhook func([]byte) ([]byte, error)
	if s.recorddir != "" {
		var recorddir string
		uniqID := p.ChallengeContext().(*challengeContext).UniqID
		recorddir = path.Join(s.recorddir, uniqID)
		err := os.MkdirAll(recorddir, 0700)
		if err != nil {
			log.Errorf("cannot create screen recording dir %v: %v", recorddir, err)
			return
		}
		recorder := newAsciicastLogger(recorddir,
			p.ChallengeContext().(*challengeContext).Username,
			p.ChallengeContext().(*challengeContext).Target)
		defer recorder.Close()

		uphook = recorder.uphook
		downhook = recorder.downhook
	}

	err := p.WaitWithHook(uphook, downhook)

	log.Infof("connection from %v closed reason: %v", conn.RemoteAddr(), err)

	s.createRecording(p.DownstreamConnMeta(), p.ChallengeContext())
}

func (s *SSHServer) parseUserAndTarget(sshuser string) (string, *common.Target, error) {
	seps := strings.SplitN(sshuser, ":", 2)
	if len(seps) != 2 {
		return "", nil, errUserFormat
	}
	user := seps[0]
	targetName := seps[1]
	target := s.api.GetTargetByName(targetName)
	if target == nil {
		return "", nil, errTargetNotFound
	}
	return user, target, nil
}

func (s *SSHServer) supportedMethods(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
	var methods []string
	methods = append(methods, "publickey")
	return methods, nil
}

func (s *SSHServer) findAndCreateUpstream(conn ssh.ConnMetadata, publicKey ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	user := challengeCtx.(*challengeContext).Username
	target := challengeCtx.(*challengeContext).Target

	pubkeys := s.api.GetPubkeysByUsername(user)
	for _, pubkey := range pubkeys {
		authedPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey.Key))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key [%v]", pubkey.Key)
		}
		if bytes.Equal(authedPubkey.Marshal(), publicKey.Marshal()) {
			pubkey.UsedAt = time.Now()
			s.api.PubkeyUsedAt(pubkey)
			addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			clientConfig := ssh.ClientConfig{
				User:            target.User,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.privateKey)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
			clientConfig.SetDefaults()
			return &ssh.Upstream{
				Conn:         c,
				Address:      addr,
				ClientConfig: clientConfig,
			}, nil
		}
	}

	return nil, fmt.Errorf("no matching public key found for user [%v]", user)
}

func (s *SSHServer) banner(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) string {
	sshuser := conn.User()

	user, target, err := s.parseUserAndTarget(sshuser)

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

	challengeCtx.(*challengeContext).Username = user
	challengeCtx.(*challengeContext).Target = target
	return ""
}

func (s *SSHServer) createChallengeContext(conn ssh.ConnMetadata) (ssh.ChallengeContext, error) {
	uiq, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	ctx := &challengeContext{
		UniqID: uiq.String(),
	}

	return ctx, nil
}

func (p *SSHServer) createRecording(_ ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) {
	username := challengeCtx.(*challengeContext).Username
	target := challengeCtx.(*challengeContext).Target

	user := p.api.GetUserByName(username)

	if user == nil {
		return
	}

	recording := common.Recording{
		UserID:   user.ID,
		TargetID: target.ID,
		RecordID: challengeCtx.(*challengeContext).UniqID,
	}

	p.api.CreateRecording(recording)
}

func NewServer(config *common.Config) (*SSHServer, error) {
	privateKey, err := os.ReadFile(config.PrivateKey)
	if err != nil {
		return nil, err
	}

	hostKey, err := os.ReadFile(config.HostKey)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(privateKey)

	if err != nil {
		return nil, err
	}

	api, err := common.NewAPI(config.DB)
	if err != nil {
		return nil, err
	}

	server := &SSHServer{
		hostKey:    hostKey,
		privateKey: signer,
		port:       config.SSHPort,
		host:       config.Host,
		api:        api,
		recorddir:  config.RecordingsDir,
	}

	return server, nil
}
