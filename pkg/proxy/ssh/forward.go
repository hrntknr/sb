package ssh

import (
	"io"

	cryptossh "golang.org/x/crypto/ssh"
)

func forwardChannel(upstream *cryptossh.Client, ch cryptossh.NewChannel, allow func(*cryptossh.Request) bool) {
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
	go forwardRequests(localRequests, remote, allow)
	go forwardRequests(remoteRequests, local, nil)
	pipe(local, remote)
}

func pipe(local, remote cryptossh.Channel) {
	go func() {
		_, _ = io.Copy(remote, local)
		_ = remote.CloseWrite()
	}()
	_, _ = io.Copy(local, remote)
	_ = local.CloseWrite()
	_ = local.Close()
	_ = remote.Close()
}

func forwardRequests(requests <-chan *cryptossh.Request, channel cryptossh.Channel, allow func(*cryptossh.Request) bool) {
	for req := range requests {
		if allow != nil && !allow(req) {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		forwardRequest(channel, req)
	}
}

func forwardRequest(channel cryptossh.Channel, req *cryptossh.Request) {
	ok, err := channel.SendRequest(req.Type, req.WantReply, req.Payload)
	if req.WantReply {
		req.Reply(err == nil && ok, nil)
	}
}
