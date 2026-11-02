#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { analyzeCapture } from './analyze.js';
import { readCapture } from './pcap.js';

interface Options {
  input: string;
  json: string | undefined;
  top: number;
  protocol: string | undefined;
  host: string | undefined;
}

function parseArgs(args: string[]): Options {
  let input = '';
  let json: string | undefined;
  let top = 10;
  let protocol: string | undefined;
  let host: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--json') json = args[++i] ?? '-';
    else if (arg === '--top') {
      const value = Number(args[++i]);
      if (!Number.isInteger(value) || value < 1 || value > 100) throw new Error('--top must be an integer between 1 and 100');
      top = value;
    } else if (arg === '--protocol') protocol = args[++i]?.toUpperCase();
    else if (arg === '--host') host = args[++i];
    else if (arg === '--help' || arg === '-h') {
      process.stdout.write('PacketLens — PCAP and PCAPNG traffic analysis\n\nUsage: packetlens <capture.pcap|capture.pcapng> [--top N] [--protocol TCP] [--host 192.0.2.1] [--json report.json]\n');
      process.exit(0);
    } else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else if (!input) input = arg;
    else throw new Error(`Unexpected argument: ${arg}`);
  }
  if (!input) throw new Error('A capture file path is required. Use --help for usage.');
  return { input, json, top, protocol, host };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const path = resolve(options.input);
  const capture = await readCapture(path);
  const filtered = capture.packets.filter(packet => (!options.protocol || packet.protocol === options.protocol) && (!options.host || packet.source === options.host || packet.destination === options.host));
  const analysis = analyzeCapture(path, capture.format, filtered);
  if (options.json) {
    const output = JSON.stringify({ ...analysis, packetRecords: undefined }, null, 2);
    if (options.json === '-') process.stdout.write(`${output}\n`);
    else await writeFile(resolve(options.json), `${output}\n`, 'utf8');
  }
  if (options.json === '-') return;
  process.stdout.write(`\nPacketLens ${analysis.format.toUpperCase()} report\n`);
  process.stdout.write(`${'─'.repeat(58)}\n`);
  process.stdout.write(`Capture     ${analysis.file}\nPackets     ${analysis.packets.toLocaleString()}\nCaptured    ${formatBytes(analysis.capturedBytes)}\nProtocols   ${Object.entries(analysis.protocols).map(([name, count]) => `${name} ${count}`).join(' · ') || 'none'}\n`);
  process.stdout.write(`\nTop hosts\n`);
  for (const host of analysis.hosts.slice(0, options.top)) process.stdout.write(`  ${host.address.padEnd(40)} ${String(host.packets).padStart(6)} packets  ${formatBytes(host.bytes)}\n`);
  process.stdout.write(`\nTop conversations\n`);
  for (const conversation of analysis.conversations.slice(0, options.top)) process.stdout.write(`  ${conversation.source} ↔ ${conversation.destination}  ${conversation.protocol}  ${conversation.packets} packets  ${formatBytes(conversation.bytes)}\n`);
  process.stdout.write(`\nSecurity findings: ${analysis.findings.length}\n`);
  for (const finding of analysis.findings) process.stdout.write(`  [${finding.severity.toUpperCase()}] ${finding.title} — ${finding.evidence}\n`);
  if (analysis.findings.length === 0) process.stdout.write('  No configured heuristic matched this capture. This is not proof that traffic is safe.\n');
  if (options.json && options.json !== '-') process.stdout.write(`\nJSON report written to ${resolve(options.json)}\n`);
}

main().catch(error => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`packetlens: ${message}\n`);
  process.exitCode = 2;
});
