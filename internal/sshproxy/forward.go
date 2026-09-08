package sshproxy

import (
	"io"

	cryptossh "golang.org/x/crypto/ssh"
)

// forwardChannel bridges a downstream channel to the upstream, filtering
// downstream requests through allow when non-nil.
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

// forwardGlobalRequests relays connection-global requests (remote port
// forwarding, keepalives) to the upstream connection, including reply
// payloads such as the port assigned by "tcpip-forward 0". When forwarding
// is not allowed, requests are rejected so remote forwarding does not
// silently pass.
func forwardGlobalRequests(requests <-chan *cryptossh.Request, upstream *cryptossh.Client, allow bool) {
	for req := range requests {
		if !allow {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := upstream.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(err == nil && ok, payload)
		}
	}
}

// reverseForwardChannels opens channels the upstream initiates
// (forwarded-tcpip) back on the downstream client connection.
func reverseForwardChannels(server *cryptossh.ServerConn, upstream *cryptossh.Client) {
	for ch := range upstream.HandleChannelOpen("forwarded-tcpip") {
		remote, requests, err := server.OpenChannel("forwarded-tcpip", ch.ExtraData())
		if err != nil {
			ch.Reject(cryptossh.ConnectionFailed, err.Error())
			continue
		}
		go cryptossh.DiscardRequests(requests)
		go func() {
			local, _, err := ch.Accept()
			if err != nil {
				remote.Close()
				return
			}
			go pipe(local, remote)
		}()
	}
}
