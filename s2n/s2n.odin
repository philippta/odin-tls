package s2n

import "core:c"

foreign import s2ntls "system:s2n"

Success :: 0
Failure :: -1
Callback_Blocked :: -2
Minimum_Supported_TLS_Record_Major_Version :: 2
Maximum_Supported_TLS_Record_Major_Version :: 3
SSLv2 :: 20
SSLv3 :: 30
TLS10 :: 31
TLS11 :: 32
TLS12 :: 33
TLS13 :: 34
Unknown_Protocol_Version :: 0

Error_Type :: enum c.int {
	Ok = 0,
	Io,
	Closed,
	Blocked,
	Alert,
	Proto,
	Internal,
	Usage,
}

Fips_Mode :: enum c.int {
	Disabled = 0,
	Enabled,
}

TLS_Extension_Type :: enum c.int {
	Server_Name              = 0,
	Max_Frag_Len             = 1,
	Ocsp_Stapling            = 5,
	Supported_Groups         = 10,
	Ec_Point_Formats         = 11,
	Signature_Algorithms     = 13,
	Alpn                     = 16,
	Certificate_Transparency = 18,
	Supported_Versions       = 43,
	Renegotiation_Info       = 65281,
}

Max_Frag_Len :: enum c.int {
	F512  = 1,
	F1024 = 2,
	F2048 = 3,
	F4096 = 4,
}

Verify_After_Sign :: enum c.int {
	Disabled,
	Enabled,
}

Status_Request_Type :: enum c.int {
	None = 0,
	Ocsp = 1,
}

CT_Support_Level :: enum c.int {
	None    = 0,
	Request = 1,
}

Alert_Behavior :: enum c.int {
	Fail_On_Warnings = 0,
	Ignore_Warnings  = 1,
}

Mode :: enum c.int {
	Server,
	Client,
}

Client_Hello_CB_Mode :: enum c.int {
	Blocking,
	Nonblocking,
}

Blinding :: enum c.int {
	Built_In,
	Self_Service,
}

Peer_Key_Update :: enum c.int {
	Not_Requested = 0,
	Requested,
}

Blocked_Status :: enum c.int {
	Not_Blocked = 0,
	Blocked_On_Read,
	Blocked_On_Write,
	Blocked_On_Application_Input,
	Blocked_On_Early_Data,
}

Cert_Auth_Type :: enum c.int {
	None,
	Required,
	Optional,
}

TLS_Signature_Algorithm :: enum c.int {
	Anonymous = 0,
	Rsa = 1,
	Ecdsa = 3,
	Mldsa = 9,
	Rsa_Pss_Rsae = 224,
	Rsa_Pss_Pss,
}

TLS_Hash_Algorithm :: enum c.int {
	None     = 0,
	Md5      = 1,
	Sha1     = 2,
	Sha224   = 3,
	Sha256   = 4,
	Sha384   = 5,
	Sha512   = 6,
	Md5_Sha1 = 224,
}

PSK_Hmac :: enum c.int {
	Sha256,
	Sha384,
}

PSK_Mode :: enum c.int {
	Resumption,
	External,
}

Cert_SNI_Match :: enum c.int {
	None = 1,
	Exact_Match,
	Wildcard_Match,
	No_Match,
}

Async_Pkey_Validation_Mode :: enum c.int {
	Fast,
	Strict,
}

Async_Pkey_Op_Type :: enum c.int {
	Decrypt,
	Sign,
}

Early_Data_Status :: enum c.int {
	Ok,
	Not_Requested,
	Rejected,
	End,
}

Serialization_Version :: enum c.int {
	None = 0,
	V1   = 1,
}

Pkey :: struct {}
Cert_Chain_And_Key :: struct {}
Session_Ticket :: struct {}
Offered_PSK_List :: struct {}
Async_Pkey_Op :: struct {}
Offered_Early_Data :: struct {}

Cert_Public_Key :: Pkey
Cert_Private_Key :: Pkey

Clock_Time_Nanoseconds :: proc "c" (ctx: rawptr, time_in_nanoseconds: ^c.uint64_t) -> c.int
Cache_Retrieve_Callback :: proc "c" (
	conn: ^Connection,
	ctx: rawptr,
	key: rawptr,
	key_size: c.uint64_t,
	value: rawptr,
	value_size: ^c.uint64_t,
) -> c.int
Cache_Store_Callback :: proc "c" (
	conn: ^Connection,
	ctx: rawptr,
	ttl_in_seconds: c.uint64_t,
	key: rawptr,
	key_size: c.uint64_t,
	value: rawptr,
	value_size: c.uint64_t,
) -> c.int
Cache_Delete_Callback :: proc "c" (
	conn: ^Connection,
	ctx: rawptr,
	key: rawptr,
	key_size: c.uint64_t,
) -> c.int

Mem_Init_Callback :: proc "c" () -> c.int
Mem_Cleanup_Callback :: proc "c" () -> c.int
Mem_Malloc_Callback :: proc "c" (
	ptr: ^rawptr,
	requested: c.uint32_t,
	allocated: ^c.uint32_t,
) -> c.int
Mem_Free_Callback :: proc "c" (ptr: rawptr, size: c.uint32_t) -> c.int

Rand_Init_Callback :: proc "c" () -> c.int
Rand_Cleanup_Callback :: proc "c" () -> c.int
Rand_Seed_Callback :: proc "c" (data: rawptr, size: c.uint32_t) -> c.int
Rand_Mix_Callback :: proc "c" (data: rawptr, size: c.uint32_t) -> c.int

Cert_Tiebreak_Callback :: proc "c" (
	cert1: ^Cert_Chain_And_Key,
	cert2: ^Cert_Chain_And_Key,
	name: ^c.uint8_t,
	name_len: c.uint32_t,
) -> ^Cert_Chain_And_Key
Verify_Host_Fn :: proc "c" (host_name: cstring, host_name_len: c.size_t, data: rawptr) -> c.uint8_t

Client_Hello_Fn :: proc "c" (conn: ^Connection, ctx: rawptr) -> c.int
Recv_Fn :: proc "c" (io_context: rawptr, buf: ^c.uint8_t, len: c.uint32_t) -> c.int
Send_Fn :: proc "c" (io_context: rawptr, buf: ^c.uint8_t, len: c.uint32_t) -> c.int

Session_Ticket_Fn :: proc "c" (conn: ^Connection, ctx: rawptr, ticket: ^Session_Ticket) -> c.int
PSK_Selection_Callback :: proc "c" (
	conn: ^Connection,
	ctx: rawptr,
	psk_list: ^Offered_PSK_List,
) -> c.int
Async_Pkey_Fn :: proc "c" (conn: ^Connection, op: ^Async_Pkey_Op) -> c.int
Key_Log_Fn :: proc "c" (
	ctx: rawptr,
	conn: ^Connection,
	logline: ^c.uint8_t,
	len: c.size_t,
) -> c.int
Early_Data_CB :: proc "c" (conn: ^Connection, early_data: ^Offered_Early_Data) -> c.int

Config :: struct {}
Connection :: struct {}
Client_Hello :: struct {}
Cert :: struct {}
PSK :: struct {}
Offered_PSK :: struct {}
Stacktrace :: struct {}

Iovec :: struct {
	iov_base: rawptr,
	iov_len:  c.size_t,
}

foreign s2ntls {
	// init / cleanup
	s2n_init :: proc() -> c.int ---
	s2n_cleanup :: proc() -> c.int ---
	s2n_cleanup_final :: proc() -> c.int ---
	s2n_crypto_disable_init :: proc() -> c.int ---
	s2n_disable_atexit :: proc() -> c.int ---
	s2n_get_openssl_version :: proc() -> c.ulong ---
	s2n_get_fips_mode :: proc(fips_mode: ^Fips_Mode) -> c.int ---

	// error
	s2n_errno_location :: proc() -> ^c.int ---
	s2n_error_get_type :: proc(error: c.int) -> c.int ---
	s2n_strerror :: proc(error: c.int, lang: cstring) -> cstring ---
	s2n_strerror_debug :: proc(error: c.int, lang: cstring) -> cstring ---
	s2n_strerror_name :: proc(error: c.int) -> cstring ---
	s2n_strerror_source :: proc(error: c.int) -> cstring ---

	// stack traces
	s2n_stack_traces_enabled :: proc() -> bool ---
	s2n_stack_traces_enabled_set :: proc(newval: bool) -> c.int ---
	s2n_calculate_stacktrace :: proc() -> c.int ---
	s2n_print_stacktrace :: proc(fptr: rawptr) -> c.int ---
	s2n_free_stacktrace :: proc() -> c.int ---
	s2n_get_stacktrace :: proc(trace: ^Stacktrace) -> c.int ---

	// config: new / free
	s2n_config_new :: proc() -> ^Config ---
	s2n_config_new_minimal :: proc() -> ^Config ---
	s2n_config_free :: proc(config: ^Config) -> c.int ---
	s2n_config_free_dhparams :: proc(config: ^Config) -> c.int ---
	s2n_config_free_cert_chain_and_key :: proc(config: ^Config) -> c.int ---

	// config: clocks
	s2n_config_set_wall_clock :: proc(config: ^Config, clock_fn: Clock_Time_Nanoseconds, ctx: rawptr) -> c.int ---
	s2n_config_set_monotonic_clock :: proc(config: ^Config, clock_fn: Clock_Time_Nanoseconds, ctx: rawptr) -> c.int ---

	// config: cache callbacks
	s2n_config_set_cache_store_callback :: proc(config: ^Config, cb: Cache_Store_Callback, data: rawptr) -> c.int ---
	s2n_config_set_cache_retrieve_callback :: proc(config: ^Config, cb: Cache_Retrieve_Callback, data: rawptr) -> c.int ---
	s2n_config_set_cache_delete_callback :: proc(config: ^Config, cb: Cache_Delete_Callback, data: rawptr) -> c.int ---

	// global mem / rand callbacks
	s2n_mem_set_callbacks :: proc(init: Mem_Init_Callback, cleanup: Mem_Cleanup_Callback, malloc: Mem_Malloc_Callback, free: Mem_Free_Callback) -> c.int ---
	s2n_rand_set_callbacks :: proc(init: Rand_Init_Callback, cleanup: Rand_Cleanup_Callback, seed: Rand_Seed_Callback, mix: Rand_Mix_Callback) -> c.int ---

	// cert chain and key
	s2n_cert_chain_and_key_new :: proc() -> ^Cert_Chain_And_Key ---
	s2n_cert_chain_and_key_load_pem :: proc(chain_and_key: ^Cert_Chain_And_Key, chain_pem: cstring, private_key_pem: cstring) -> c.int ---
	s2n_cert_chain_and_key_load_pem_bytes :: proc(chain_and_key: ^Cert_Chain_And_Key, chain_pem: ^c.uint8_t, chain_pem_len: c.uint32_t, private_key_pem: ^c.uint8_t, private_key_pem_len: c.uint32_t) -> c.int ---
	s2n_cert_chain_and_key_load_public_pem_bytes :: proc(chain_and_key: ^Cert_Chain_And_Key, chain_pem: ^c.uint8_t, chain_pem_len: c.uint32_t) -> c.int ---
	s2n_cert_chain_and_key_free :: proc(cert_and_key: ^Cert_Chain_And_Key) -> c.int ---
	s2n_cert_chain_and_key_set_ctx :: proc(cert_and_key: ^Cert_Chain_And_Key, ctx: rawptr) -> c.int ---
	s2n_cert_chain_and_key_get_ctx :: proc(cert_and_key: ^Cert_Chain_And_Key) -> rawptr ---
	s2n_cert_chain_and_key_get_private_key :: proc(cert_and_key: ^Cert_Chain_And_Key) -> ^Cert_Private_Key ---
	s2n_cert_chain_and_key_set_ocsp_data :: proc(chain_and_key: ^Cert_Chain_And_Key, data: ^c.uint8_t, length: c.uint32_t) -> c.int ---
	s2n_cert_chain_and_key_set_sct_list :: proc(chain_and_key: ^Cert_Chain_And_Key, data: ^c.uint8_t, length: c.uint32_t) -> c.int ---

	// config: cert / trust store
	s2n_config_set_cert_tiebreak_callback :: proc(config: ^Config, cb: Cert_Tiebreak_Callback) -> c.int ---
	s2n_config_add_cert_chain_and_key :: proc(config: ^Config, cert_chain_pem: cstring, private_key_pem: cstring) -> c.int ---
	s2n_config_add_cert_chain_and_key_to_store :: proc(config: ^Config, cert_key_pair: ^Cert_Chain_And_Key) -> c.int ---
	s2n_config_set_cert_chain_and_key_defaults :: proc(config: ^Config, cert_key_pairs: ^^Cert_Chain_And_Key, num_cert_key_pairs: c.uint32_t) -> c.int ---
	s2n_config_set_verification_ca_location :: proc(config: ^Config, ca_pem_filename: cstring, ca_dir: cstring) -> c.int ---
	s2n_config_add_pem_to_trust_store :: proc(config: ^Config, pem: cstring) -> c.int ---
	s2n_config_wipe_trust_store :: proc(config: ^Config) -> c.int ---
	s2n_config_load_system_certs :: proc(config: ^Config) -> c.int ---
	s2n_config_set_cert_authorities_from_trust_store :: proc(config: ^Config) -> c.int ---

	// config: verification / x509
	s2n_config_set_verify_after_sign :: proc(config: ^Config, mode: Verify_After_Sign) -> c.int ---
	s2n_config_set_verify_host_callback :: proc(config: ^Config, host_fn: Verify_Host_Fn, data: rawptr) -> c.int ---
	s2n_config_set_check_stapled_ocsp_response :: proc(config: ^Config, check_ocsp: c.uint8_t) -> c.int ---
	s2n_config_disable_x509_time_verification :: proc(config: ^Config) -> c.int ---
	s2n_config_disable_x509_verification :: proc(config: ^Config) -> c.int ---
	s2n_config_set_max_cert_chain_depth :: proc(config: ^Config, max_depth: c.uint16_t) -> c.int ---

	// config: cipher / protocol / extensions
	s2n_config_add_dhparams :: proc(config: ^Config, dhparams_pem: cstring) -> c.int ---
	s2n_config_set_cipher_preferences :: proc(config: ^Config, version: cstring) -> c.int ---
	s2n_config_append_protocol_preference :: proc(config: ^Config, protocol: ^c.uint8_t, protocol_len: c.uint8_t) -> c.int ---
	s2n_config_set_protocol_preferences :: proc(config: ^Config, protocols: ^cstring, protocol_count: c.int) -> c.int ---
	s2n_config_set_status_request_type :: proc(config: ^Config, type: Status_Request_Type) -> c.int ---
	s2n_config_set_ct_support_level :: proc(config: ^Config, level: CT_Support_Level) -> c.int ---
	s2n_config_set_alert_behavior :: proc(config: ^Config, alert_behavior: Alert_Behavior) -> c.int ---
	s2n_config_set_extension_data :: proc(config: ^Config, type: TLS_Extension_Type, data: ^c.uint8_t, length: c.uint32_t) -> c.int ---
	s2n_config_send_max_fragment_length :: proc(config: ^Config, mfl_code: Max_Frag_Len) -> c.int ---
	s2n_config_accept_max_fragment_length :: proc(config: ^Config) -> c.int ---

	// config: buffers / io
	s2n_config_set_send_buffer_size :: proc(config: ^Config, size: c.uint32_t) -> c.int ---
	s2n_config_set_recv_multi_record :: proc(config: ^Config, enabled: bool) -> c.int ---

	// config: session / tickets
	s2n_config_set_session_state_lifetime :: proc(config: ^Config, lifetime_in_secs: c.uint64_t) -> c.int ---
	s2n_config_set_session_tickets_onoff :: proc(config: ^Config, enabled: c.uint8_t) -> c.int ---
	s2n_config_set_session_cache_onoff :: proc(config: ^Config, enabled: c.uint8_t) -> c.int ---
	s2n_config_set_ticket_encrypt_decrypt_key_lifetime :: proc(config: ^Config, lifetime_in_secs: c.uint64_t) -> c.int ---
	s2n_config_set_ticket_decrypt_key_lifetime :: proc(config: ^Config, lifetime_in_secs: c.uint64_t) -> c.int ---
	s2n_config_add_ticket_crypto_key :: proc(config: ^Config, name: ^c.uint8_t, name_len: c.uint32_t, key: ^c.uint8_t, key_len: c.uint32_t, intro_time_in_seconds_from_epoch: c.uint64_t) -> c.int ---
	s2n_config_require_ticket_forward_secrecy :: proc(config: ^Config, enabled: bool) -> c.int ---
	s2n_config_set_initial_ticket_count :: proc(config: ^Config, num: c.uint8_t) -> c.int ---
	s2n_config_set_session_ticket_cb :: proc(config: ^Config, callback: Session_Ticket_Fn, ctx: rawptr) -> c.int ---

	// config: ctx
	s2n_config_set_ctx :: proc(config: ^Config, ctx: rawptr) -> c.int ---
	s2n_config_get_ctx :: proc(config: ^Config, ctx: ^rawptr) -> c.int ---

	// config: client hello callback
	s2n_config_set_client_hello_cb :: proc(config: ^Config, cb: Client_Hello_Fn, ctx: rawptr) -> c.int ---
	s2n_config_set_client_hello_cb_mode :: proc(config: ^Config, cb_mode: Client_Hello_CB_Mode) -> c.int ---

	// config: auth
	s2n_config_get_client_auth_type :: proc(config: ^Config, client_auth_type: ^Cert_Auth_Type) -> c.int ---
	s2n_config_set_client_auth_type :: proc(config: ^Config, client_auth_type: Cert_Auth_Type) -> c.int ---

	// config: async pkey
	s2n_config_set_async_pkey_callback :: proc(config: ^Config, fn: Async_Pkey_Fn) -> c.int ---
	s2n_config_set_async_pkey_validation_mode :: proc(config: ^Config, mode: Async_Pkey_Validation_Mode) -> c.int ---

	// config: key log
	s2n_config_set_key_log_cb :: proc(config: ^Config, callback: Key_Log_Fn, ctx: rawptr) -> c.int ---

	// config: blinding
	s2n_config_set_max_blinding_delay :: proc(config: ^Config, seconds: c.uint32_t) -> c.int ---

	// config: early data
	s2n_config_set_server_max_early_data_size :: proc(config: ^Config, max_early_data_size: c.uint32_t) -> c.int ---
	s2n_config_set_early_data_cb :: proc(config: ^Config, cb: Early_Data_CB) -> c.int ---
	s2n_config_enable_cert_req_dss_legacy_compat :: proc(config: ^Config) -> c.int ---

	// config: psk
	s2n_config_set_psk_mode :: proc(config: ^Config, mode: PSK_Mode) -> c.int ---
	s2n_config_set_psk_selection_callback :: proc(config: ^Config, cb: PSK_Selection_Callback, ctx: rawptr) -> c.int ---

	// config: supported groups / serialization
	s2n_config_get_supported_groups :: proc(config: ^Config, groups: ^c.uint16_t, groups_count_max: c.uint16_t, groups_count: ^c.uint16_t) -> c.int ---
	s2n_config_set_serialization_version :: proc(config: ^Config, version: Serialization_Version) -> c.int ---

	// connection: new / free / wipe
	s2n_connection_new :: proc(mode: Mode) -> ^Connection ---
	s2n_connection_set_config :: proc(conn: ^Connection, config: ^Config) -> c.int ---
	s2n_connection_wipe :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_free :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_free_handshake :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_release_buffers :: proc(conn: ^Connection) -> c.int ---

	// connection: ctx
	s2n_connection_set_ctx :: proc(conn: ^Connection, ctx: rawptr) -> c.int ---
	s2n_connection_get_ctx :: proc(conn: ^Connection) -> rawptr ---

	// connection: fd / io
	s2n_connection_set_fd :: proc(conn: ^Connection, fd: c.int) -> c.int ---
	s2n_connection_set_read_fd :: proc(conn: ^Connection, readfd: c.int) -> c.int ---
	s2n_connection_set_write_fd :: proc(conn: ^Connection, writefd: c.int) -> c.int ---
	s2n_connection_get_read_fd :: proc(conn: ^Connection, readfd: ^c.int) -> c.int ---
	s2n_connection_get_write_fd :: proc(conn: ^Connection, writefd: ^c.int) -> c.int ---
	s2n_connection_use_corked_io :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_set_recv_ctx :: proc(conn: ^Connection, ctx: rawptr) -> c.int ---
	s2n_connection_set_send_ctx :: proc(conn: ^Connection, ctx: rawptr) -> c.int ---
	s2n_connection_set_recv_cb :: proc(conn: ^Connection, recv: Recv_Fn) -> c.int ---
	s2n_connection_set_send_cb :: proc(conn: ^Connection, send: Send_Fn) -> c.int ---

	// connection: tuning
	s2n_connection_prefer_throughput :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_prefer_low_latency :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_set_recv_buffering :: proc(conn: ^Connection, enabled: bool) -> c.int ---
	s2n_connection_set_dynamic_buffers :: proc(conn: ^Connection, enabled: bool) -> c.int ---
	s2n_connection_set_dynamic_record_threshold :: proc(conn: ^Connection, resize_threshold: c.uint32_t, timeout_threshold: c.uint16_t) -> c.int ---
	s2n_peek :: proc(conn: ^Connection) -> c.uint32_t ---
	s2n_peek_buffered :: proc(conn: ^Connection) -> c.uint32_t ---

	// connection: verify host / blinding
	s2n_connection_set_verify_host_callback :: proc(conn: ^Connection, host_fn: Verify_Host_Fn, data: rawptr) -> c.int ---
	s2n_connection_set_blinding :: proc(conn: ^Connection, blinding: Blinding) -> c.int ---
	s2n_connection_get_delay :: proc(conn: ^Connection) -> c.uint64_t ---

	// connection: cipher / protocol preferences
	s2n_connection_set_cipher_preferences :: proc(conn: ^Connection, version: cstring) -> c.int ---
	s2n_connection_request_key_update :: proc(conn: ^Connection, peer_request: Peer_Key_Update) -> c.int ---
	s2n_connection_append_protocol_preference :: proc(conn: ^Connection, protocol: ^c.uint8_t, protocol_len: c.uint8_t) -> c.int ---
	s2n_connection_set_protocol_preferences :: proc(conn: ^Connection, protocols: ^cstring, protocol_count: c.int) -> c.int ---

	// connection: server name / application protocol
	s2n_set_server_name :: proc(conn: ^Connection, server_name: cstring) -> c.int ---
	s2n_get_server_name :: proc(conn: ^Connection) -> cstring ---
	s2n_get_application_protocol :: proc(conn: ^Connection) -> cstring ---

	// connection: ocsp / sct
	s2n_connection_get_ocsp_response :: proc(conn: ^Connection, length: ^c.uint32_t) -> ^c.uint8_t ---
	s2n_connection_get_sct_list :: proc(conn: ^Connection, length: ^c.uint32_t) -> ^c.uint8_t ---

	// connection: handshake / io
	s2n_negotiate :: proc(conn: ^Connection, blocked: ^Blocked_Status) -> c.int ---
	s2n_send :: proc(conn: ^Connection, buf: rawptr, size: c.ssize_t, blocked: ^Blocked_Status) -> c.ssize_t ---
	s2n_sendv :: proc(conn: ^Connection, bufs: ^Iovec, count: c.ssize_t, blocked: ^Blocked_Status) -> c.ssize_t ---
	s2n_sendv_with_offset :: proc(conn: ^Connection, bufs: ^Iovec, count: c.ssize_t, offs: c.ssize_t, blocked: ^Blocked_Status) -> c.ssize_t ---
	s2n_recv :: proc(conn: ^Connection, buf: rawptr, size: c.ssize_t, blocked: ^Blocked_Status) -> c.ssize_t ---
	s2n_shutdown :: proc(conn: ^Connection, blocked: ^Blocked_Status) -> c.int ---
	s2n_shutdown_send :: proc(conn: ^Connection, blocked: ^Blocked_Status) -> c.int ---

	// connection: client hello
	s2n_client_hello_cb_done :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_server_name_extension_used :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_client_hello :: proc(conn: ^Connection) -> ^Client_Hello ---
	s2n_client_hello_parse_message :: proc(bytes: ^c.uint8_t, size: c.uint32_t) -> ^Client_Hello ---
	s2n_client_hello_free :: proc(ch: ^^Client_Hello) -> c.int ---
	s2n_client_hello_get_raw_message_length :: proc(ch: ^Client_Hello) -> c.ssize_t ---
	s2n_client_hello_get_raw_message :: proc(ch: ^Client_Hello, out: ^c.uint8_t, max_length: c.uint32_t) -> c.ssize_t ---
	s2n_client_hello_get_cipher_suites_length :: proc(ch: ^Client_Hello) -> c.ssize_t ---
	s2n_client_hello_get_cipher_suites :: proc(ch: ^Client_Hello, out: ^c.uint8_t, max_length: c.uint32_t) -> c.ssize_t ---
	s2n_client_hello_get_extensions_length :: proc(ch: ^Client_Hello) -> c.ssize_t ---
	s2n_client_hello_get_extensions :: proc(ch: ^Client_Hello, out: ^c.uint8_t, max_length: c.uint32_t) -> c.ssize_t ---
	s2n_client_hello_get_extension_length :: proc(ch: ^Client_Hello, extension_type: TLS_Extension_Type) -> c.ssize_t ---
	s2n_client_hello_get_extension_by_id :: proc(ch: ^Client_Hello, extension_type: TLS_Extension_Type, out: ^c.uint8_t, max_length: c.uint32_t) -> c.ssize_t ---
	s2n_client_hello_has_extension :: proc(ch: ^Client_Hello, extension_iana: c.uint16_t, exists: ^bool) -> c.int ---
	s2n_client_hello_get_session_id_length :: proc(ch: ^Client_Hello, out_length: ^c.uint32_t) -> c.int ---
	s2n_client_hello_get_session_id :: proc(ch: ^Client_Hello, out: ^c.uint8_t, out_length: ^c.uint32_t, max_length: c.uint32_t) -> c.int ---
	s2n_client_hello_get_compression_methods_length :: proc(ch: ^Client_Hello, out_length: ^c.uint32_t) -> c.int ---
	s2n_client_hello_get_compression_methods :: proc(ch: ^Client_Hello, list: ^c.uint8_t, list_length: c.uint32_t, out_length: ^c.uint32_t) -> c.int ---
	s2n_client_hello_get_legacy_protocol_version :: proc(ch: ^Client_Hello, out: ^c.uint8_t) -> c.int ---
	s2n_client_hello_get_legacy_record_version :: proc(ch: ^Client_Hello, out: ^c.uint8_t) -> c.int ---
	s2n_client_hello_get_random :: proc(ch: ^Client_Hello, out: ^c.uint8_t, max_length: c.uint32_t) -> c.int ---
	s2n_client_hello_get_supported_groups :: proc(ch: ^Client_Hello, groups: ^c.uint16_t, groups_count_max: c.uint16_t, groups_count: ^c.uint16_t) -> c.int ---
	s2n_client_hello_get_server_name_length :: proc(ch: ^Client_Hello, length: ^c.uint16_t) -> c.int ---
	s2n_client_hello_get_server_name :: proc(ch: ^Client_Hello, server_name: ^c.uint8_t, length: c.uint16_t, out_length: ^c.uint16_t) -> c.int ---

	// connection: auth
	s2n_connection_get_client_auth_type :: proc(conn: ^Connection, client_auth_type: ^Cert_Auth_Type) -> c.int ---
	s2n_connection_set_client_auth_type :: proc(conn: ^Connection, client_auth_type: Cert_Auth_Type) -> c.int ---
	s2n_connection_get_client_cert_chain :: proc(conn: ^Connection, der_cert_chain_out: ^^c.uint8_t, cert_chain_len: ^c.uint32_t) -> c.int ---
	s2n_connection_client_cert_used :: proc(conn: ^Connection) -> c.int ---

	// connection: session / tickets
	s2n_connection_add_new_tickets_to_send :: proc(conn: ^Connection, num: c.uint8_t) -> c.int ---
	s2n_connection_get_tickets_sent :: proc(conn: ^Connection, num: ^c.uint16_t) -> c.int ---
	s2n_connection_set_server_keying_material_lifetime :: proc(conn: ^Connection, lifetime_in_secs: c.uint32_t) -> c.int ---
	s2n_session_ticket_get_data_len :: proc(ticket: ^Session_Ticket, data_len: ^c.size_t) -> c.int ---
	s2n_session_ticket_get_data :: proc(ticket: ^Session_Ticket, max_data_len: c.size_t, data: ^c.uint8_t) -> c.int ---
	s2n_session_ticket_get_lifetime :: proc(ticket: ^Session_Ticket, session_lifetime: ^c.uint32_t) -> c.int ---
	s2n_connection_set_session :: proc(conn: ^Connection, session: ^c.uint8_t, length: c.size_t) -> c.int ---
	s2n_connection_get_session :: proc(conn: ^Connection, session: ^c.uint8_t, max_length: c.size_t) -> c.int ---
	s2n_connection_get_session_ticket_lifetime_hint :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_session_length :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_session_id_length :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_session_id :: proc(conn: ^Connection, session_id: ^c.uint8_t, max_length: c.size_t) -> c.int ---
	s2n_connection_is_session_resumed :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_is_ocsp_stapled :: proc(conn: ^Connection) -> c.int ---

	// connection: negotiated parameters
	s2n_connection_get_selected_signature_algorithm :: proc(conn: ^Connection, chosen_alg: ^TLS_Signature_Algorithm) -> c.int ---
	s2n_connection_get_selected_digest_algorithm :: proc(conn: ^Connection, chosen_alg: ^TLS_Hash_Algorithm) -> c.int ---
	s2n_connection_get_selected_client_cert_signature_algorithm :: proc(conn: ^Connection, chosen_alg: ^TLS_Signature_Algorithm) -> c.int ---
	s2n_connection_get_selected_client_cert_digest_algorithm :: proc(conn: ^Connection, chosen_alg: ^TLS_Hash_Algorithm) -> c.int ---
	s2n_connection_get_signature_scheme :: proc(conn: ^Connection, scheme_name: ^cstring) -> c.int ---
	s2n_connection_get_selected_cert :: proc(conn: ^Connection) -> ^Cert_Chain_And_Key ---
	s2n_connection_get_client_protocol_version :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_server_protocol_version :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_actual_protocol_version :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_client_hello_version :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_cipher :: proc(conn: ^Connection) -> cstring ---
	s2n_connection_get_certificate_match :: proc(conn: ^Connection, match_status: ^Cert_SNI_Match) -> c.int ---
	s2n_connection_get_master_secret :: proc(conn: ^Connection, secret_bytes: ^c.uint8_t, max_size: c.size_t) -> c.int ---
	s2n_connection_tls_exporter :: proc(conn: ^Connection, label: ^c.uint8_t, label_length: c.uint32_t, ctx: ^c.uint8_t, context_length: c.uint32_t, output: ^c.uint8_t, output_length: c.uint32_t) -> c.int ---
	s2n_connection_get_cipher_iana_value :: proc(conn: ^Connection, first: ^c.uint8_t, second: ^c.uint8_t) -> c.int ---
	s2n_connection_is_valid_for_cipher_preferences :: proc(conn: ^Connection, version: cstring) -> c.int ---
	s2n_connection_get_curve :: proc(conn: ^Connection) -> cstring ---
	s2n_connection_get_kem_name :: proc(conn: ^Connection) -> cstring ---
	s2n_connection_get_kem_group_name :: proc(conn: ^Connection) -> cstring ---
	s2n_connection_get_key_exchange_group :: proc(conn: ^Connection, group_name: ^cstring) -> c.int ---
	s2n_connection_get_alert :: proc(conn: ^Connection) -> c.int ---
	s2n_connection_get_handshake_type_name :: proc(conn: ^Connection) -> cstring ---
	s2n_connection_get_last_message_name :: proc(conn: ^Connection) -> cstring ---
	s2n_connection_get_wire_bytes_in :: proc(conn: ^Connection) -> c.uint64_t ---
	s2n_connection_get_wire_bytes_out :: proc(conn: ^Connection) -> c.uint64_t ---

	// connection: cert chain inspection
	s2n_cert_chain_get_length :: proc(chain_and_key: ^Cert_Chain_And_Key, cert_length: ^c.uint32_t) -> c.int ---
	s2n_cert_chain_get_cert :: proc(chain_and_key: ^Cert_Chain_And_Key, out_cert: ^^Cert, cert_idx: c.uint32_t) -> c.int ---
	s2n_cert_get_der :: proc(cert: ^Cert, out_cert_der: ^^c.uint8_t, cert_length: ^c.uint32_t) -> c.int ---
	s2n_connection_get_peer_cert_chain :: proc(conn: ^Connection, cert_chain: ^Cert_Chain_And_Key) -> c.int ---
	s2n_cert_get_x509_extension_value_length :: proc(cert: ^Cert, oid: ^c.uint8_t, ext_value_len: ^c.uint32_t) -> c.int ---
	s2n_cert_get_x509_extension_value :: proc(cert: ^Cert, oid: ^c.uint8_t, ext_value: ^c.uint8_t, ext_value_len: ^c.uint32_t, critical: ^bool) -> c.int ---
	s2n_cert_get_utf8_string_from_extension_data_length :: proc(extension_data: ^c.uint8_t, extension_len: c.uint32_t, utf8_str_len: ^c.uint32_t) -> c.int ---
	s2n_cert_get_utf8_string_from_extension_data :: proc(extension_data: ^c.uint8_t, extension_len: c.uint32_t, out_data: ^c.uint8_t, out_len: ^c.uint32_t) -> c.int ---

	// async pkey ops
	s2n_async_pkey_op_perform :: proc(op: ^Async_Pkey_Op, key: ^Cert_Private_Key) -> c.int ---
	s2n_async_pkey_op_apply :: proc(op: ^Async_Pkey_Op, conn: ^Connection) -> c.int ---
	s2n_async_pkey_op_free :: proc(op: ^Async_Pkey_Op) -> c.int ---
	s2n_async_pkey_op_get_op_type :: proc(op: ^Async_Pkey_Op, type: ^Async_Pkey_Op_Type) -> c.int ---
	s2n_async_pkey_op_get_input_size :: proc(op: ^Async_Pkey_Op, data_len: ^c.uint32_t) -> c.int ---
	s2n_async_pkey_op_get_input :: proc(op: ^Async_Pkey_Op, data: ^c.uint8_t, data_len: c.uint32_t) -> c.int ---
	s2n_async_pkey_op_set_output :: proc(op: ^Async_Pkey_Op, data: ^c.uint8_t, data_len: c.uint32_t) -> c.int ---

	// psk
	s2n_external_psk_new :: proc() -> ^PSK ---
	s2n_psk_free :: proc(psk: ^^PSK) -> c.int ---
	s2n_psk_set_identity :: proc(psk: ^PSK, identity: ^c.uint8_t, identity_size: c.uint16_t) -> c.int ---
	s2n_psk_set_secret :: proc(psk: ^PSK, secret: ^c.uint8_t, secret_size: c.uint16_t) -> c.int ---
	s2n_psk_set_hmac :: proc(psk: ^PSK, hmac: PSK_Hmac) -> c.int ---
	s2n_connection_append_psk :: proc(conn: ^Connection, psk: ^PSK) -> c.int ---
	s2n_connection_set_psk_mode :: proc(conn: ^Connection, mode: PSK_Mode) -> c.int ---
	s2n_connection_get_negotiated_psk_identity_length :: proc(conn: ^Connection, identity_length: ^c.uint16_t) -> c.int ---
	s2n_connection_get_negotiated_psk_identity :: proc(conn: ^Connection, identity: ^c.uint8_t, max_identity_length: c.uint16_t) -> c.int ---
	s2n_offered_psk_new :: proc() -> ^Offered_PSK ---
	s2n_offered_psk_free :: proc(psk: ^^Offered_PSK) -> c.int ---
	s2n_offered_psk_get_identity :: proc(psk: ^Offered_PSK, identity: ^^c.uint8_t, size: ^c.uint16_t) -> c.int ---
	s2n_offered_psk_list_has_next :: proc(psk_list: ^Offered_PSK_List) -> bool ---
	s2n_offered_psk_list_next :: proc(psk_list: ^Offered_PSK_List, psk: ^Offered_PSK) -> c.int ---
	s2n_offered_psk_list_reread :: proc(psk_list: ^Offered_PSK_List) -> c.int ---
	s2n_offered_psk_list_choose_psk :: proc(psk_list: ^Offered_PSK_List, psk: ^Offered_PSK) -> c.int ---

	// early data
	s2n_connection_set_server_max_early_data_size :: proc(conn: ^Connection, max_early_data_size: c.uint32_t) -> c.int ---
	s2n_connection_set_server_early_data_context :: proc(conn: ^Connection, ctx: ^c.uint8_t, context_size: c.uint16_t) -> c.int ---
	s2n_psk_configure_early_data :: proc(psk: ^PSK, max_early_data_size: c.uint32_t, cipher_suite_first_byte: c.uint8_t, cipher_suite_second_byte: c.uint8_t) -> c.int ---
	s2n_psk_set_application_protocol :: proc(psk: ^PSK, application_protocol: ^c.uint8_t, size: c.uint8_t) -> c.int ---
	s2n_psk_set_early_data_context :: proc(psk: ^PSK, ctx: ^c.uint8_t, size: c.uint16_t) -> c.int ---
	s2n_connection_get_early_data_status :: proc(conn: ^Connection, status: ^Early_Data_Status) -> c.int ---
	s2n_connection_get_remaining_early_data_size :: proc(conn: ^Connection, allowed_early_data_size: ^c.uint32_t) -> c.int ---
	s2n_connection_get_max_early_data_size :: proc(conn: ^Connection, max_early_data_size: ^c.uint32_t) -> c.int ---
	s2n_send_early_data :: proc(conn: ^Connection, data: ^c.uint8_t, data_len: c.ssize_t, data_sent: ^c.ssize_t, blocked: ^Blocked_Status) -> c.int ---
	s2n_recv_early_data :: proc(conn: ^Connection, data: ^c.uint8_t, max_data_len: c.ssize_t, data_received: ^c.ssize_t, blocked: ^Blocked_Status) -> c.int ---
	s2n_offered_early_data_get_context_length :: proc(early_data: ^Offered_Early_Data, context_len: ^c.uint16_t) -> c.int ---
	s2n_offered_early_data_get_context :: proc(early_data: ^Offered_Early_Data, ctx: ^c.uint8_t, max_len: c.uint16_t) -> c.int ---
	s2n_offered_early_data_reject :: proc(early_data: ^Offered_Early_Data) -> c.int ---
	s2n_offered_early_data_accept :: proc(early_data: ^Offered_Early_Data) -> c.int ---

	// serialization
	s2n_connection_serialization_length :: proc(conn: ^Connection, length: ^c.uint32_t) -> c.int ---
	s2n_connection_serialize :: proc(conn: ^Connection, buffer: ^c.uint8_t, buffer_length: c.uint32_t) -> c.int ---
	s2n_connection_deserialize :: proc(conn: ^Connection, buffer: ^c.uint8_t, buffer_length: c.uint32_t) -> c.int ---
}
