// Fails when package.json and Cargo.toml disagree about the version.
//
// package.json is a version-only file (name, version, private). It exists
// because the org's Release version check treats removing a version from it
// as a reset; the crate is the real source of the version. Bump both together.
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("package.json", "utf8")).version;
const cargo = /^\[package\][^[]*?^version\s*=\s*"([^"]+)"/ms.exec(
  readFileSync("Cargo.toml", "utf8"),
)?.[1];

if (!pkg || !cargo || pkg !== cargo) {
  console.error(`package.json is ${pkg} but Cargo.toml is ${cargo}`);
  process.exit(1);
}
console.log(`version ${cargo}`);
