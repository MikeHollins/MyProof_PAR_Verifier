#!/usr/bin/env node

try {
  // Keep the emitted entry path exact while placing module loading inside the
  // same last-resort safety boundary as command execution. This ensures an
  // incomplete/corrupt package reports internal 70 rather than Node's raw
  // module-resolution exit and stack trace.
  const { main } = await import("../dist/cli/main.js");
  process.exitCode = await main();
} catch {
  // Keep the executable's last-resort path safe and deterministic. Normal
  // errors are handled by the adapter and never reach this branch.
  process.stderr.write("myproof-par: internal verifier failure [CLI_INTERNAL]\n");
  process.exitCode = 70;
}
