#!/usr/bin/env node
import { runCli, shouldUseColor } from './cli.js';

process.exitCode = await runCli(process.argv.slice(2), {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
  color: shouldUseColor(process.stdout.isTTY, process.env),
});
