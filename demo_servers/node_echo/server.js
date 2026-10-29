// demo_servers/node_echo/server.js  (safe on purpose)
//
// A minimal MCP server over stdio with no dependencies, written in plain Node. It exists to
// exercise TrustProbe's Node sandbox image end to end. It speaks just enough of the protocol
// (initialize, ping, tools/list, tools/call) for a scan; it has no prompts or resources.
"use strict";
const readline = require("node:readline");

const TOOL = {
  name: "echo",
  description: "Echo a short message back.",
  inputSchema: {
    type: "object",
    properties: { text: { type: "string", maxLength: 200 } },
    required: ["text"],
    additionalProperties: false,
  },
};

function send(message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
}

function handle(msg) {
  if (msg.id === undefined) return; // notifications need no reply
  switch (msg.method) {
    case "initialize":
      return send({
        id: msg.id,
        result: {
          protocolVersion: (msg.params && msg.params.protocolVersion) || "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "node-echo", version: "1.0.0" },
        },
      });
    case "ping":
      return send({ id: msg.id, result: {} });
    case "tools/list":
      return send({ id: msg.id, result: { tools: [TOOL] } });
    case "tools/call": {
      const args = (msg.params && msg.params.arguments) || {};
      return send({ id: msg.id, result: { content: [{ type: "text", text: String(args.text) }] } });
    }
    default:
      return send({ id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } });
  }
}

readline.createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  try {
    handle(JSON.parse(line));
  } catch (err) {
    send({ id: null, error: { code: -32700, message: "Parse error" } });
  }
});
