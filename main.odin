package main

import "core:fmt"
import "core:nbio"
import "nbtls"

main :: proc() {
	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	socket, err := nbio.listen_tcp({nbio.IP4_Any, 8443})
	assert(err == nil)

	nbtls.accept_with_cert_and_key_file(
		socket,
		"example.local.pem",
		"example.local-key.pem",
		accept_cb,
	)
	nbio.run()
}

accept_cb :: proc(op: nbtls.Operation) {
	fmt.println("accepted")

	buf := make([]byte, 1024)
	nbtls.recv(op.socket, op.conn, buf, recv_cb)
}

recv_cb :: proc(op: nbtls.Operation) {
	fmt.println("received")

	nbtls.send(op.socket, op.conn, op.buf, send_cb)
}

send_cb :: proc(op: nbtls.Operation) {
	fmt.println("sent")

	delete(op.buf)

	nbtls.close(op.socket, op.conn, close_cb)
}

close_cb :: proc(op: nbtls.Operation) {
	fmt.println("closed")
}
