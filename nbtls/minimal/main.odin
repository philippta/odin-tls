package main

import "core:fmt"
import "core:nbio"
import "core:net"

main :: proc() {
	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	socket, err := nbio.listen_tcp({nbio.IP4_Any, 8080})
	assert(err == nil)
	fmt.println("listening on :8080")

	nbio.accept(socket, accept_cb)
	nbio.run()
}

accept_cb :: proc(op: ^nbio.Operation) {
	assert(op.accept.err == nil)
	client := op.accept.client
	fmt.println("accepted:", client)

	// re-arm accept
	nbio.accept(op.accept.socket, accept_cb)

	// wait for first data
	nbio.poll_poly(client, .Receive, client, on_readable)
}

on_readable :: proc(op: ^nbio.Operation, client: nbio.TCP_Socket) {
	fmt.println("poll fired for:", client)

	buf: [1024]byte
	nbio.recv_poly(client, {buf[:]}, client, on_recv)
}

on_recv :: proc(op: ^nbio.Operation, client: nbio.TCP_Socket) {
	if op.recv.err != nil {
		fmt.println("recv err:", op.recv.err)
		nbio.close(op.recv.socket.(nbio.TCP_Socket))
		return
	}
	if op.recv.received == 0 {
		fmt.println("connection closed by peer")
		nbio.close(op.recv.socket.(nbio.TCP_Socket))
		return
	}

	data := op.recv.bufs[0][:op.recv.received]
	fmt.println("received", op.recv.received, "bytes:")
	fmt.println(string(data))

	// echo it back
	response := make([]byte, op.recv.received)
	copy(response, data)
	nbio.send_poly(client, {response}, client, on_sent)
}

on_sent :: proc(op: ^nbio.Operation, client: nbio.TCP_Socket) {
	if op.send.err != nil {
		fmt.println("send err:", op.send.err)
		nbio.close(op.send.socket.(nbio.TCP_Socket))
		return
	}
	fmt.println("sent", op.send.sent, "bytes")

	// wait for next data
	nbio.poll_poly(client, .Receive, client, on_readable)
}
