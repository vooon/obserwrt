/* obserwrt - ucode `-c` syntax-check stub header
 *
 * Loaded via `sed`/concatenation in CI before compiling each agent module to
 * bytecode (ucode -c, never executed). ucode resolves imports at compile time,
 * but the OpenWrt-specific modules (bpf, uci, ubus, uloop, ...) are not part of
 * the upstream ucode tree, so the import/export lines are stripped first and
 * this header supplies the referenced names for the compile-only pass.
 */
function open_module() {}
function tc_detach() {}
function bpf_error() {}
function connect() {}
function cursor() {}
function readfile() {}
function ulog_open() {}
function ulog() {}
function INFO() {}
function NOTE() {}
function WARN() {}
function ERR() {}
const struct = {
	pack:   function() { return ''; },
	unpack: function() { return []; },
	new:    function() { return { pack: function() { return ''; }, unpack: function() { return []; } }; },
};
