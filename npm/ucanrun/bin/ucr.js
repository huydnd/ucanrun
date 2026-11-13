#!/usr/bin/env node
"use strict";
// Runs the native ucr from the platform package npm installed next to this
// one (@ucanrun/<platform>-<arch>), passing arguments, stdio and the exit
// code through. MCP clients talk to it over stdin and stdout.
const {spawn} = require("child_process");
const path = require("path");

const pkg = `@ucanrun/${process.platform}-${process.arch}`;
const exe = process.platform === "win32" ? "ucr.exe" : "ucr";
let bin;
try {
  bin = path.join(path.dirname(require.resolve(`${pkg}/package.json`)), "bin", exe);
} catch (_) {
  process.stderr.write(
    `ucanrun: no build for ${process.platform}-${process.arch} (package ${pkg} is missing).\n` +
    "Builds exist for linux-x64, linux-arm64, darwin-x64, darwin-arm64 and win32-x64.\n" +
    "If npm skipped optional dependencies, reinstall without --omit=optional / --no-optional.\n" +
    "Other systems: https://github.com/huydnd/ucanrun/releases\n");
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), {stdio: "inherit", windowsHide: true});
// Ctrl+C reaches the child through the terminal; other signals are passed on.
for (const sig of ["SIGTERM", "SIGHUP"]) {
  process.on(sig, () => { try { child.kill(sig); } catch (_) {} });
}
child.on("error", e => { process.stderr.write(`ucanrun: cannot start ${bin}: ${e.message}\n`); process.exit(1); });
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code == null ? 1 : code);
});
