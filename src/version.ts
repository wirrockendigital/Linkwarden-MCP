// This module centralizes server identity values so protocol metadata and tools stay in sync.

export const MCP_SERVER_NAME = 'linkwarden-mcp';
export const MCP_SERVER_VERSION = '0.2.22';
export const MCP_PROTOCOL_VERSION = '2025-03-26';

// This helper formats one date segment with two digits for stable protocol metadata output.
function pad2(value: number): string {
  return String(value).padStart(2, '0');
}

// This helper returns protocol version metadata extended with local timestamp for diagnostics.
export function formatProtocolVersionWithTimestamp(now = new Date()): string {
  const datePart = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}`;
  const timePart = `${pad2(now.getHours())}-${pad2(now.getMinutes())}-${pad2(now.getSeconds())}`;
  return `${MCP_PROTOCOL_VERSION} - ${datePart} - ${timePart}`;
}
