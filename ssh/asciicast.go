package ssh

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sshmux/common"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

const (
	msgChannelRequest     = 98
	msgChannelOpenConfirm = 91
	msgChannelData        = 94
)

func jsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	s := string(b)
	return s[1 : len(s)-1]
}

func readString(buf *bytes.Reader) string {
	var l uint32
	err := binary.Read(buf, binary.BigEndian, &l)
	if err != nil {
		return ""
	}
	s := make([]byte, l)
	_, err = buf.Read(s)
	if err != nil {
		return ""
	}
	return string(s)
}

type channelMeta struct {
	cmd             string
	starttime       time.Time
	initWidth       uint32
	initHeight      uint32
	displayedBanner bool
	envs            map[string]string
	f               *os.File
}

type asciicastLogger struct {
	channels     map[uint32]*channelMeta
	channelIDMap map[uint32]uint32
	recorddir    string
	user         string
	target       *common.Target
}

func newAsciicastLogger(recorddir string, user string, target *common.Target) *asciicastLogger {
	return &asciicastLogger{
		recorddir:    recorddir,
		channels:     make(map[uint32]*channelMeta),
		channelIDMap: make(map[uint32]uint32),
		user:         user,
		target:       target,
	}
}

func (l *asciicastLogger) prependBanner(clientChannelID uint32, buf []byte) []byte {
	messageBuf := bytes.NewBuffer(nil)
	color.New(color.BgGreen, color.FgBlack, color.Bold).Fprintf(messageBuf, " ✓ SSHMUX connected ")
	color.New(color.Reset, color.ResetBold).Fprintf(messageBuf, " pipe %s to %s\n\r", l.user, l.target.Name)
	message := messageBuf.Bytes()

	msg2 := []byte{msgChannelData}
	msg2 = binary.BigEndian.AppendUint32(msg2, clientChannelID)
	msg2 = binary.BigEndian.AppendUint32(msg2, uint32(len(message)+len(buf)))
	msg2 = append(msg2, message...)
	msg2 = append(msg2, buf...)
	return msg2
}

func (l *asciicastLogger) uphook(msg []byte) ([]byte, error) {
	if msg[0] == 80 {
		// filter host keys requests
		var x struct {
			RequestName string `sshtype:"80"`
		}
		_ = ssh.Unmarshal(msg, &x)
		if x.RequestName == "hostkeys-prove-00@openssh.com" || x.RequestName == "hostkeys-00@openssh.com" {
			return nil, nil
		}
	} else if msg[0] == msgChannelData {
		clientChannelID := binary.BigEndian.Uint32(msg[1:5])

		meta, ok := l.channels[clientChannelID]
		if ok {
			buf := msg[9:]
			t := time.Since(meta.starttime).Seconds()

			_, err := fmt.Fprintf(meta.f, "[%v,\"o\",\"%s\"]\n", t, jsonEscape(string(buf)))

			if err != nil {
				return msg, err
			}

			if !meta.displayedBanner {
				meta.displayedBanner = true
				if meta.envs["TERM"] == "xterm-color" || strings.HasSuffix(meta.envs["TERM"], "-256color") {
					return l.prependBanner(clientChannelID, buf), nil
				}
			}
		}
	} else if msg[0] == msgChannelOpenConfirm {
		clientChannelID := binary.BigEndian.Uint32(msg[1:5])
		serverChannelID := binary.BigEndian.Uint32(msg[5:9])
		l.channelIDMap[serverChannelID] = clientChannelID
	}
	return msg, nil
}

func (l *asciicastLogger) downhook(msg []byte) ([]byte, error) {
	if msg[0] == msgChannelRequest {
		serverChannelID := binary.BigEndian.Uint32(msg[1:5])
		clientChannelID := l.channelIDMap[serverChannelID]
		buf := bytes.NewReader(msg[5:])
		reqType := readString(buf)
		if _, ok := l.channels[clientChannelID]; !ok {
			l.channels[clientChannelID] = &channelMeta{
				envs: make(map[string]string),
			}
		}
		meta := l.channels[clientChannelID]

		switch reqType {
		case "pty-req":
			_, _ = buf.ReadByte()
			term := readString(buf)
			_ = binary.Read(buf, binary.BigEndian, &meta.initWidth)
			_ = binary.Read(buf, binary.BigEndian, &meta.initHeight)
			meta.envs["TERM"] = term
		case "env":
			_, _ = buf.ReadByte()
			varName := readString(buf)
			varValue := readString(buf)
			meta.envs[varName] = varValue
		case "window-change":
			_, _ = buf.ReadByte()
			var width, height uint32
			_ = binary.Read(buf, binary.BigEndian, &width)
			_ = binary.Read(buf, binary.BigEndian, &height)
			t := time.Since(meta.starttime).Seconds()
			_, err := fmt.Fprintf(meta.f, "[%v,\"r\", \"%vx%v\"]\n", t, width, height)
			if err != nil {
				return msg, err
			}
		case "shell", "exec":
			jsonEnvs, err := json.Marshal(meta.envs)

			if err != nil {
				return msg, err
			}

			f, err := os.OpenFile(
				path.Join(l.recorddir, fmt.Sprintf("%s-channel-%d.cast", reqType, clientChannelID)),
				os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
				0600,
			)

			if err != nil {
				return msg, err
			}

			meta.f = f
			meta.displayedBanner = false
			meta.starttime = time.Now()

			var header string
			header = fmt.Sprintf(
				"{\"version\": 2, \"width\": %d, \"height\": %d, \"timestamp\": %d, \"env\": %v",
				meta.initWidth,
				meta.initHeight,
				meta.starttime.Unix(),
				string(jsonEnvs),
			)

			if reqType == "exec" {
				_, _ = buf.ReadByte()
				meta.cmd = readString(buf)
				header += fmt.Sprintf(", \"command\": \"%s\"}\n", jsonEscape(meta.cmd))
			} else {
				header += "}\n"
			}

			_, err = fmt.Fprint(meta.f, header)

			if err != nil {
				return msg, err
			}
		}
	}
	return msg, nil
}

func (l *asciicastLogger) Close() (err error) {
	for _, meta := range l.channels {
		_ = meta.f.Close()
	}
	return nil
}
