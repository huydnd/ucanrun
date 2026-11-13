#!/usr/bin/env node
// Builds the npm packages for one release from the release binaries.
//   node npm/build.mjs <version> <dir with ucr-<os>-<arch>[.exe]> <out dir>
// Writes <out>/ucanrun and <out>/<platform> package folders, ready for
// `npm publish`. Platform packages first, then ucanrun, which depends on them.
import {cpSync, mkdirSync, readFileSync, writeFileSync, chmodSync, existsSync, rmSync} from "node:fs";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";

const [version, dist, out] = process.argv.slice(2);
if (!version || !dist || !out || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error("usage: node npm/build.mjs <version> <binaries dir> <out dir>");
  process.exit(2);
}
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
// npm platform name -> release binary name.
const targets = [
  {os: "linux", cpu: "x64", file: "ucr-linux-amd64"},
  {os: "linux", cpu: "arm64", file: "ucr-linux-arm64"},
  {os: "darwin", cpu: "x64", file: "ucr-darwin-amd64"},
  {os: "darwin", cpu: "arm64", file: "ucr-darwin-arm64"},
  {os: "win32", cpu: "x64", file: "ucr-windows-amd64.exe"},
];
const only = (process.env.UCANRUN_NPM_TARGETS || "").split(",").filter(Boolean);
const main = JSON.parse(readFileSync(join(here, "ucanrun", "package.json"), "utf8"));
rmSync(out, {recursive: true, force: true});

const deps = {};
for (const t of targets) {
  const name = `@ucanrun/${t.os}-${t.cpu}`;
  if (only.length && !only.includes(`${t.os}-${t.cpu}`)) continue;
  const src = join(dist, t.file);
  if (!existsSync(src)) { console.error(`missing ${src}`); process.exit(1); }
  const dir = join(out, `${t.os}-${t.cpu}`);
  const exe = t.os === "win32" ? "ucr.exe" : "ucr";
  mkdirSync(join(dir, "bin"), {recursive: true});
  cpSync(src, join(dir, "bin", exe));
  chmodSync(join(dir, "bin", exe), 0o755);
  writeFileSync(join(dir, "package.json"), JSON.stringify({
    name, version,
    description: `The ${t.os}-${t.cpu} build of ucr, for the ucanrun package.`,
    homepage: main.homepage, repository: main.repository, license: main.license,
    os: [t.os], cpu: [t.cpu],
    files: ["bin/"],
    preferUnplugged: true,
  }, null, 2) + "\n");
  writeFileSync(join(dir, "README.md"), `The ${t.os}-${t.cpu} build of \`ucr\`. Install [ucanrun](https://www.npmjs.com/package/ucanrun) instead; it picks this package for you.\n`);
  cpSync(join(root, "LICENSE"), join(dir, "LICENSE"));
  deps[name] = version;
}

const dir = join(out, "ucanrun");
cpSync(join(here, "ucanrun"), dir, {recursive: true});
cpSync(join(root, "LICENSE"), join(dir, "LICENSE"));
main.version = version;
main.optionalDependencies = deps;
writeFileSync(join(dir, "package.json"), JSON.stringify(main, null, 2) + "\n");
chmodSync(join(dir, "bin", "ucr.js"), 0o755);
console.log(`built ${Object.keys(deps).length + 1} packages for ${version} in ${out}`);
