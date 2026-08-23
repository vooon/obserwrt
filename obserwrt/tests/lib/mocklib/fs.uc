/* obserwrt - filesystem module mock
 *
 * reconcile.uc (imported by exporter_syslog for ifname() resolution) reads
 * `readfile` from 'fs'. The syslog tests never call it, but the module must
 * resolve at import time, so provide a deterministic stub.
 */
"use strict";

function readfile(path) { return null; }

export { readfile };