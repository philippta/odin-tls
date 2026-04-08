package main

import "core:c"
import "core:fmt"
import "core:net"
import "core:strings"

foreign import lib {"system:ssl.3", "system:crypto.3"}

SSL_METHOD :: struct {}
SSL_CTX :: struct {}
SSL :: struct {}
SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
SSL_FILETYPE_PEM :: 1
SSL_FILETYPE_ASN1 :: 2
SSL_FILETYPE_DEFAULT :: 3
TLSEXT_NAMETYPE_host_name :: 0

foreign lib {
	TLS_client_method :: proc() -> ^SSL_METHOD ---
	TLS_server_method :: proc() -> ^SSL_METHOD ---
	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_CTX_use_certificate_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_set_rfd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_set_wfd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_connect :: proc(ssl: ^SSL) -> c.int ---
	SSL_accept :: proc(ssl: ^SSL) -> c.int ---
	SSL_ctrl :: proc(ssl: ^SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_write :: proc(ssl: ^SSL, buf: [^]byte, num: c.int) -> c.int ---
	SSL_read :: proc(ssl: ^SSL, buf: [^]byte, num: c.int) -> c.int ---
	SSL_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_get_error :: proc(ssl: ^SSL, ret: c.int) -> c.int ---
	ERR_get_error :: proc() -> c.int ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]byte, len: c.size_t) ---
}

TLS_Method :: enum {
	TLS_Method_Client,
	TLS_Method_Server,
}

TLS_Config :: struct {
	ssl_ctx: ^SSL_CTX,
}

TLS :: struct {
	config: ^TLS_Config,
	ssl:    ^SSL,
	socket: net.TCP_Socket,
}

TLS_Error :: union {
	net.Network_Error,
}

tls_config_init :: proc(tls_config: ^TLS_Config, method: TLS_Method) {
	switch method {
	case .TLS_Method_Client:
		tls_config.ssl_ctx = SSL_CTX_new(TLS_client_method())
	case .TLS_Method_Server:
		tls_config.ssl_ctx = SSL_CTX_new(TLS_server_method())
	}
	assert(tls_config.ssl_ctx != nil)
}

tls_config_init_client :: proc(tls_config: ^TLS_Config) {
	tls_config_init(tls_config, .TLS_Method_Client)
}

tls_config_init_server :: proc(tls_config: ^TLS_Config) {
	tls_config_init(tls_config, .TLS_Method_Server)
}

tls_config_destroy :: proc(tls_config: ^TLS_Config) {
	SSL_CTX_free(tls_config.ssl_ctx)
}

tls_init :: proc(tls: ^TLS, tls_config: ^TLS_Config) {
	tls.config = tls_config
	tls.ssl = SSL_new(tls_config.ssl_ctx)
}

tls_init_with_servername :: proc(tls: ^TLS, tls_config: ^TLS_Config, servername: string) {
	tls_init(tls, tls_config)

	servername_cstring := strings.clone_to_cstring(servername)
	defer delete(servername_cstring)

	SSL_set_tlsext_host_name(tls.ssl, servername_cstring)
}

tls_destroy :: proc(tls: ^TLS) {
	SSL_free(tls.ssl)
}

tls_close :: proc(tls: ^TLS) {
	SSL_shutdown(tls.ssl)
	net.close(tls.socket)
}

tls_dial :: proc {
	tls_dial_from_hostname_and_port_string,
}

tls_dial_from_hostname_and_port_string :: proc(tls: ^TLS, hostname_and_port: string) -> TLS_Error {
	tls.socket = net.dial_tcp(hostname_and_port) or_return

	ret := SSL_set_fd(tls.ssl, c.int(tls.socket))
	assert(ret == 1)

	ret = SSL_connect(tls.ssl)
	assert(ret == 1)

	return nil
}

tls_listen :: proc(tls: ^TLS, ep: net.Endpoint, cert: string, key: string) -> TLS_Error {
	tls.socket = net.listen_tcp(ep) or_return

	cert_cstring := strings.clone_to_cstring(cert)
	defer delete(cert_cstring)

	key_cstring := strings.clone_to_cstring(key)
	defer delete(key_cstring)

	assert(SSL_CTX_use_certificate_file(tls.config.ssl_ctx, cert_cstring, SSL_FILETYPE_PEM) > 0)
	assert(SSL_CTX_use_PrivateKey_file(tls.config.ssl_ctx, key_cstring, SSL_FILETYPE_PEM) > 0)

	return nil
}

tls_accept :: proc(tls: ^TLS) -> ^TLS {
	socket, _, err := net.accept_tcp(tls.socket)
	assert(err == nil)

	client := new(TLS)
	tls_init(client, tls.config)
	SSL_set_fd(client.ssl, c.int(socket))
	assert(SSL_accept(client.ssl) == 1)

	return client
}

tls_send :: proc(conn: ^TLS, buf: []byte) -> (bytes_written: int) {
	ret := SSL_write(conn.ssl, raw_data(buf), c.int(len(buf)))
	return int(ret)
}

tls_recv :: proc(conn: ^TLS, buf: []byte) -> (bytes_read: int) {
	ret := SSL_read(conn.ssl, raw_data(buf), c.int(len(buf)))
	assert(ret > 0)
	return int(ret)
}


main :: proc() {
	{
		cfg: TLS_Config
		tls_config_init_client(&cfg)
		defer tls_config_destroy(&cfg)

		tls: TLS
		tls_init_with_servername(&tls, &cfg, "flyscrape.com")

		err := tls_dial(&tls, "flyscrape.com:443")
		assert(err == nil)

		msg := "GET / HTTP/1.1\r\nHost: flyscrape.com\r\n\r\n"
		tls_send(&tls, transmute([]byte)msg)

		buf: [512]byte
		tls_recv(&tls, buf[:])

		fmt.println(string(buf[:]))

		tls_close(&tls)
		tls_destroy(&tls)
	}

	{
		cfg: TLS_Config
		tls_config_init_server(&cfg)
		defer tls_config_destroy(&cfg)


		tls: TLS
		tls_init(&tls, &cfg)

		tls_listen(&tls, {net.IP4_Any, 8443}, "foobar.local.pem", "foobar.local-key.pem")

		client := tls_accept(&tls)
		defer tls_destroy(client)
		defer tls_close(client)

		msg := "Hello world\n"
		n := tls_send(client, transmute([]byte)msg)
		fmt.println(n)
	}


}

SSL_print_error :: proc(ssl: ^SSL, ret: c.int) {
	err := SSL_get_error(ssl, ret)
	fmt.println(err)

	er := ERR_get_error()
	fmt.println(er)

	buf: [256]byte
	ERR_error_string_n(c.ulong(er), raw_data(buf[:]), len(buf))

	fmt.println(string(buf[:]))
}

SSL_set_tlsext_host_name :: proc(ssl: ^SSL, name: cstring) -> c.int {
	return c.int(SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(name)))
}
