import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const directory = path.dirname(fileURLToPath(import.meta.url));
const server = path.join(directory, "jstack_mcp_server.py");
const candidates = process.platform === "win32"
  ? [["py", ["-3"]], ["python", []], ["python3", []]]
  : [["python3", []], ["python", []]];

function launch(index) {
  if (index >= candidates.length) {
    process.stderr.write("JStack requires Python 3, but no Python launcher was found.\n");
    process.exit(127);
  }
  const [command, prefix] = candidates[index];
  const child = spawn(command, [...prefix, server], {
    cwd: directory,
    env: process.env,
    stdio: "inherit"
  });
  let started = true;
  child.once("error", (error) => {
    if (error.code === "ENOENT") {
      started = false;
      launch(index + 1);
      return;
    }
    process.stderr.write(`Failed to launch JStack MCP: ${error.message}\n`);
    process.exit(1);
  });
  child.once("exit", (code, signal) => {
    if (!started) return;
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
  const signals = process.platform === "win32" ? ["SIGINT", "SIGTERM"] : ["SIGINT", "SIGTERM", "SIGHUP"];
  for (const signal of signals) {
    process.once(signal, () => {
      if (!child.killed) child.kill(signal);
    });
  }
}

launch(0);
