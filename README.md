# nbtls

`nbtls` is a non blocking TLS server implementation based on `core:nbio` and `s2n-tls`.

## Example

```odin
package main

import nbtls ".."
import "core:fmt"
import "core:nbio"

configs: map[string]^nbtls.Config

main :: proc() {
	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	socket, err := nbio.listen_tcp({nbio.IP4_Any, 8443})
	assert(err == nil)

	nbtls.init()
	defer nbtls.destroy()

	configs = make(map[string]^nbtls.Config)

	configs["foo.local"] = nbtls.config_init_with_cert_and_key_file(
		"certs/foo.local.pem",
		"certs/foo.local-key.pem",
	)

	configs["bar.local"] = nbtls.config_init_with_cert_and_key_file(
		"certs/bar.local.pem",
		"certs/bar.local-key.pem",
	)

	nbtls.accept(socket, accept_cb)
	nbio.run()
}

accept_cb :: proc(op: ^nbtls.Operation) {
	server_name := op.accept.server_name
	fmt.println("server_name:", server_name)

	if config, ok := configs[server_name]; ok {
		nbtls.handshake(op.conn, config, handshake_cb)
	} else {
		nbtls.close(op.conn, close_cb)
	}

    // re-arm for accepting more connections
	nbtls.accept(op.accept.socket, accept_cb)
}

handshake_cb :: proc(op: ^nbtls.Operation) {
    fmt.println("handshake completed")

	buf := make([]byte, 512)
	nbtls.recv(op.conn, buf, recv_cb)
}

recv_cb :: proc(op: ^nbtls.Operation) {
    fmt.println("message received")

	if op.recv.received == 0 do return
	nbtls.send(op.conn, op.recv.buf, send_cb)
}

send_cb :: proc(op: ^nbtls.Operation) {
    fmt.println("message sent")

	if op.send.sent == 0 do return
	delete(op.send.buf)
	nbtls.close(op.conn, close_cb)
}

close_cb :: proc(op: ^nbtls.Operation) {
    fmt.println("connection closed")
}
```

# Disclaimer

This is heavily WIP and only implements the happy path so far.
