// Empty no-op agent: just say hello, do nothing else.
// Use to isolate whether agent injection itself triggers anti-debug.
send({ type: "log", msg: "noop agent up pid=" + Process.id });
rpc.exports = { ping() { return "pong"; } };
