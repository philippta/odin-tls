package main

import s2n ".."
import "core:c"
import "core:fmt"
import "core:net"

main :: proc() {
	s2n.s2n_init()
	config := s2n.s2n_config_new()
	assert(config != nil)

	socket, err := net.dial_tcp("odin-lang.org:443")
	assert(err == nil)

	conn := s2n.s2n_connection_new(.Client)
	assert(conn != nil)

	s2n.s2n_connection_set_config(conn, config)
	s2n.s2n_connection_set_fd(conn, c.int(socket))
	s2n.s2n_set_server_name(conn, "odin-lang.org")

	blocked: s2n.Blocked_Status
	ret := s2n.s2n_negotiate(conn, &blocked)
	assert(ret == s2n.Success)

	req := "GET / HTTP/1.1\r\nHost: odin-lang.org\r\nConnection: close\r\n\r\n"
	n := s2n.s2n_send(conn, raw_data(req), len(req), &blocked)
	assert(n > 0)

	resp: [4096]byte
	for {
		n := s2n.s2n_recv(conn, raw_data(resp[:]), len(resp), &blocked)
		assert(n >= 0)
		if n == 0 do break
		fmt.print(string(resp[:n]))
	}

	s2n.s2n_shutdown(conn, &blocked)
	s2n.s2n_connection_free(conn)
	s2n.s2n_config_free(config)
	net.close(socket)
	s2n.s2n_cleanup()
}
