package ssh

import (
	"io"

	cryptossh "golang.org/x/crypto/ssh"
)

func forwardChannel(upstream *cryptossh.Client, ch cryptossh.NewChannel) {
	remote, remoteRequests, err := upstream.OpenChannel(ch.ChannelType(), ch.ExtraData())
	if err != nil {
		ch.Reject(cryptossh.ConnectionFailed, err.Error())
		return
	}
	local, localRequests, err := ch.Accept()
	if err != nil {
		remote.Close()
		return
	}
	go forwardRequests(localRequests, remote)
	go forwardRequests(remoteRequests, local)
	go func() {
		_, _ = io.Copy(remote, local)
		_ = remote.CloseWrite()
	}()
	go func() {
		_, _ = io.Copy(local, remote)
		_ = local.CloseWrite()
		_ = local.Close()
		_ = remote.Close()
	}()
}

func forwardRequests(requests <-chan *cryptossh.Request, channel cryptossh.Channel) {
	for req := range requests {
		ok, err := channel.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(err == nil && ok, nil)
		}
	}
}
