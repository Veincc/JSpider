"use strict";

const path = require("node:path");
const vm = require("node:vm");
const fs = require("node:fs");
const esbuild = require("esbuild");

const repoRoot = path.resolve(__dirname, "..", "..");
const entryPath = path.join(__dirname, "src", "worker.js");
const bundlePath = path.join(repoRoot, "internal", "preprocess", "audit-prep.cjs");

esbuild.buildSync({
  entryPoints: [entryPath],
  outfile: bundlePath,
  bundle: true,
  platform: "node",
  format: "cjs",
  target: ["node18"],
  minify: false,
  legalComments: "none",
  banner: {
    js: "#!/usr/bin/env node",
  },
});

const source = fs.readFileSync(bundlePath, "utf8").replace(/^#!.*\n/, "");
new vm.Script(source, { filename: bundlePath });
console.log("Built internal/preprocess/audit-prep.cjs");
