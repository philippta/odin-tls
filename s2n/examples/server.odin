package main

import s2n ".."
import "core:c"
import "core:net"
import "core:os"
import "core:strings"

main :: proc() {
	cert_pem, _ := os.read_entire_file("example.local.pem", context.allocator)
	key_pem, _ := os.read_entire_file("example.local-key.pem", context.allocator)
	cert_pem_c := strings.clone_to_cstring(string(cert_pem))
	key_pem_c := strings.clone_to_cstring(string(key_pem))

	s2n.s2n_init()
	config := s2n.s2n_config_new()
	assert(config != nil)

	assert(s2n.s2n_config_set_cipher_preferences(config, "default") == s2n.Success)
	assert(s2n.s2n_config_add_cert_chain_and_key(config, cert_pem_c, key_pem_c) == s2n.Success)

	socket, err := net.listen_tcp({net.IP4_Any, 8443})
	assert(err == nil)

	for {
		client, _, err_accept := net.accept_tcp(socket)
		assert(err_accept == nil)

		conn := s2n.s2n_connection_new(.Server)
		s2n.s2n_connection_set_config(conn, config)
		s2n.s2n_connection_set_fd(conn, c.int(client))

		blocked: s2n.Blocked_Status
		s2n.s2n_negotiate(conn, &blocked)

		req := "Hello from Odin!\n"
		n := s2n.s2n_send(conn, raw_data(req), len(req), &blocked)
		assert(n > 0)

		s2n.s2n_shutdown(conn, &blocked)
		s2n.s2n_connection_free(conn)
		net.close(client)
	}

	s2n.s2n_config_free(config)
	net.close(socket)
	s2n.s2n_cleanup()
}
