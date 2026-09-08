package sshproxy

import (
	"io"
	"sync"

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
	// pending tracks in-flight request forwarding so the channel is not
	// closed while a request reply (e.g. the "exec" success reply) is
	// still on its way back to the downstream client.
	var pending sync.WaitGroup
	go func() {
		forwardRequests(localRequests, remote, allow, &pending)
		// The downstream channel closed; close the upstream too so remote
		// commands do not outlive the client that started them.
		_ = remote.Close()
	}()
	pipe(local, remote, remoteRequests, &pending)
}

// pipe bridges data between the downstream (local) and upstream (remote)
// channels, relaying upstream requests to the downstream. The downstream
// channel is closed only after the upstream channel closed and in-flight
// requests finished, so requests the upstream sent before closing
// (exit-status, exit-signal) are always delivered first; without this,
// clients miss the remote exit status and report the session as a connection
// failure.
func pipe(local, remote cryptossh.Channel, upstreamRequests <-chan *cryptossh.Request, pending *sync.WaitGroup) {
	go func() {
		_, _ = io.Copy(remote, local)
		_ = remote.CloseWrite()
	}()
	relayed := make(chan struct{})
	go func() {
		for req := range upstreamRequests {
			forwardRequest(local, req)
		}
		close(relayed)
	}()
	_, _ = io.Copy(local, remote)
	_ = local.CloseWrite()
	<-relayed
	pending.Wait()
	_ = local.Close()
	_ = remote.Close()
}

func forwardRequests(requests <-chan *cryptossh.Request, channel cryptossh.Channel, allow func(*cryptossh.Request) bool, pending *sync.WaitGroup) {
	for req := range requests {
		pending.Add(1)
		if allow != nil && !allow(req) {
			if req.WantReply {
				req.Reply(false, nil)
			}
		} else {
			forwardRequest(channel, req)
		}
		pending.Done()
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
		downstream, downstreamRequests, err := server.OpenChannel("forwarded-tcpip", ch.ExtraData())
		if err != nil {
			ch.Reject(cryptossh.ConnectionFailed, err.Error())
			continue
		}
		go cryptossh.DiscardRequests(downstreamRequests)
		go func() {
			upstreamCh, upstreamRequests, err := ch.Accept()
			if err != nil {
				downstream.Close()
				return
			}
			var pending sync.WaitGroup
			go pipe(downstream, upstreamCh, upstreamRequests, &pending)
		}()
	}
}
