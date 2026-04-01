import { spawn } from "child_process";
import path from "path";
import fs from "fs";
import { resolveDataDir } from "@/lib/dataPaths";
import { addDNSEntry, removeDNSEntry } from "./dns/dnsConfig";
import { generateCert } from "./cert/generate";
import { installCert } from "./cert/install";

// Store server process
let serverProcess = null;
let serverPid = null;

// Module-scoped password cache (not exposed on globalThis).
// Cleared automatically when the MITM proxy is stopped.
let _cachedPassword = null;
export function getCachedPassword() {
  return _cachedPassword;
}
export function setCachedPassword(pwd) {
  _cachedPassword = pwd || null;
}
export function clearCachedPassword() {
  _cachedPassword = null;
}

function getMitmPidFile() {
  return path.join(resolveDataDir(), "mitm", ".mitm.pid");
}
const MITM_SERVER_PATH = path.join(process.cwd(), "src", "mitm", "server.cjs");

// Check if a PID is alive
function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
// Kill any process using port 443
async function killPort443(sudoPassword) {
  const isRoot = process.getuid && process.getuid() === 0;
  const cmd = isRoot 
    ? "fuser -k 443/tcp || true" 
    : `echo "${sudoPassword}" | sudo -S fuser -k 443/tcp || true`;
  
  return new Promise((resolve) => {
    const { exec } = require("child_process");
    exec(cmd, (error) => {
      // We ignore errors because fuser returns non-zero if no process found
      resolve(true);
    });
  });
}
/**
 * Get MITM status
 */
export async function getMitmStatus() {
  // Check in-memory process first, then fallback to PID file
  let running = serverProcess !== null && !serverProcess.killed;
  let pid = serverPid;

  if (!running) {
    try {
      const pidFile = getMitmPidFile();
      if (fs.existsSync(pidFile)) {
        const savedPid = parseInt(fs.readFileSync(pidFile, "utf-8").trim(), 10);
        if (savedPid && isProcessAlive(savedPid)) {
          running = true;
          pid = savedPid;
        } else {
          // Stale PID file, clean up
          try { fs.unlinkSync(pidFile); } catch (e) {}
        }
      }
    } catch (error) {
      // Ignore
    }
  }

  // Check DNS configuration
  let dnsConfigured = false;
  try {
    const hostsContent = fs.readFileSync("/etc/hosts", "utf-8");
    dnsConfigured = hostsContent.includes("daily-cloudcode-pa.googleapis.com");
  } catch {
    // Ignore
  }

  // Check cert
  const certDir = path.join(resolveDataDir(), "mitm");
  const certExists = fs.existsSync(path.join(certDir, "server.crt"));

  return { running, pid, dnsConfigured, certExists };
}

/**
 * Start MITM proxy
 * @param {string} apiKey - OmniRoute API key
 * @param {string} sudoPassword - Sudo password for DNS/cert operations
 */
export async function startMitm(apiKey, sudoPassword) {
  // 0. Forcefully clear port 443
  console.log("Clearing port 443...");
  await killPort443(sudoPassword);
  // Small delay to allow port to be released
  await new Promise(resolve => setTimeout(resolve, 500));

  // Check if already running (in-memory)
  if (serverProcess && !serverProcess.killed) {
    serverProcess.kill("SIGKILL");
    serverProcess = null;
  }

  // 1. Generate SSL certificate if not exists
  const certPath = path.join(resolveDataDir(), "mitm", "server.crt");
  if (!fs.existsSync(certPath)) {
    console.log("Generating SSL certificate...");
    await generateCert();
  }

  // 2. Install certificate to system keychain
  await installCert(sudoPassword, certPath);

  // 3. Add DNS entry
  console.log("Adding DNS entry...");
  await addDNSEntry(sudoPassword);

  // 4. Start MITM server
  console.log("Starting MITM server...");
  serverProcess = spawn(process.execPath, [MITM_SERVER_PATH], {
    env: {
      ...process.env,
      DATA_DIR: resolveDataDir(),
      ROUTER_API_KEY: apiKey,
      NODE_ENV: "production",
    },
    detached: false,
    stdio: ["ignore", "pipe", "pipe"],
  });

  serverPid = serverProcess.pid;

  // PID is managed by the server process itself to ensure accuracy across refreshes
  // server.cjs now writes to getMitmPidFile() on startup


  // Log server output
  serverProcess.stdout.on("data", (data) => {
    console.log(`[MITM Server] ${data.toString().trim()}`);
  });

  serverProcess.stderr.on("data", (data) => {
    console.error(`[MITM Server Error] ${data.toString().trim()}`);
  });

  serverProcess.on("exit", (code) => {
    console.log(`MITM server exited with code ${code}`);
    serverProcess = null;
    serverPid = null;
  });

  // Wait and verify server actually started
  let lastError = "";
  const started = await new Promise((resolve) => {
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        resolve(true);
      }
    }, 2000);

    serverProcess.on("exit", (code) => {
      clearTimeout(timeout);
      if (!resolved) {
        resolved = true;
        resolve(false);
      }
    });

    // Check stderr for error messages
    serverProcess.stderr.on("data", (data) => {
      const msg = data.toString().trim();
      lastError = msg;
      if (msg.includes("Port") && msg.includes("already in use")) {
        clearTimeout(timeout);
        if (!resolved) {
          resolved = true;
          resolve(false);
        }
      }
    });
  });

  if (!started) {
    const detail = lastError ? `: ${lastError}` : " (port 443 may be in use)";
    throw new Error(`MITM server failed to start${detail}`);
  }

  return {
    running: true,
    pid: serverPid,
  };
}

/**
 * Stop MITM proxy
 * @param {string} sudoPassword - Sudo password for DNS cleanup
 */
export async function stopMitm(sudoPassword) {
  // 1. Kill server process (in-memory or from PID file)
  const proc = serverProcess;
  if (proc && !proc.killed) {
    console.log("Stopping MITM server...");
    proc.kill("SIGTERM");
    await new Promise((resolve) => setTimeout(resolve, 1000));
    if (!proc.killed) {
      proc.kill("SIGKILL");
    }
    serverProcess = null;
    serverPid = null;
  } else {
    // Fallback: kill by PID file
    try {
      const pidFile = getMitmPidFile();
      if (fs.existsSync(pidFile)) {
        const savedPid = parseInt(fs.readFileSync(pidFile, "utf-8").trim(), 10);
        if (savedPid && isProcessAlive(savedPid)) {
          console.log(`Killing MITM server (PID: ${savedPid})...`);
          process.kill(savedPid, "SIGTERM");
          await new Promise((resolve) => setTimeout(resolve, 1000));
          if (isProcessAlive(savedPid)) {
            process.kill(savedPid, "SIGKILL");
          }
        }
      }
    } catch {
      // Ignore
    }
    serverProcess = null;
    serverPid = null;
  }

  // 2. Remove DNS entry
  console.log("Removing DNS entry...");
  await removeDNSEntry(sudoPassword);

  // 3. Clean up
  clearCachedPassword(); // Clear password from memory when proxy stops
  try {
    const pidFile = getMitmPidFile();
    if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
  } catch (error) {
    // Ignore
  }

  return {
    running: false,
    pid: null,
  };
}
