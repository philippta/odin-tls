package main

import "core:c"
import "core:fmt"
import "core:net"

foreign import lib {"system:ssl.3", "system:crypto.3"}

SSL_METHOD :: struct {}
SSL_CTX :: struct {}
SSL :: struct {}
SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
TLSEXT_NAMETYPE_host_name :: 0

@(default_calling_convention = "c")
foreign lib {
	TLS_client_method :: proc() -> ^SSL_METHOD ---
	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_set_rfd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_set_wfd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_connect :: proc(ssl: ^SSL) -> c.int ---
	SSL_ctrl :: proc(ssl: ^SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_write :: proc(ssl: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_read :: proc(ssl: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_get_error :: proc(ssl: ^SSL, ret: c.int) -> c.int ---
	ERR_get_error :: proc() -> c.int ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]byte, len: c.size_t) ---
}

main :: proc() {
	method := TLS_client_method()
	assert(method != nil)

	ctx := SSL_CTX_new(method)
	assert(ctx != nil)

	ssl := SSL_new(ctx)
	assert(ssl != nil)

	socket, err := net.dial_tcp("flyscrape.com:443")
	assert(err == nil)

	ret := SSL_set_fd(ssl, c.int(socket))
	assert(ret == 1)

	name := cstring("flyscrape.com")
	lret := SSL_ctrl(
		ssl,
		SSL_CTRL_SET_TLSEXT_HOSTNAME,
		TLSEXT_NAMETYPE_host_name,
		transmute([^]byte)name,
	)
	assert(lret == 1)

	ret = SSL_connect(ssl)
	if ret <= 0 {
		SSL_print_error(ssl, ret)
	}
	assert(ret == 1)

	req := "GET / HTTP/1.1\r\nHost: flyscrape.com\r\n\r\n"
	ret = SSL_write(ssl, raw_data(req), c.int(len(req)))
	assert(ret > 0)


	prevn := c.int(0)
	for {
		resp: [4096]byte
		n := SSL_read(ssl, raw_data(resp[:]), c.int(len(resp)))
		assert(n > 0)
		fmt.println(string(resp[:n]))

		if n >= prevn {
			prevn = n
		} else {
			break
		}
	}

	SSL_shutdown(ssl)
	net.close(socket)
	SSL_free(ssl)
	SSL_CTX_free(ctx)
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
