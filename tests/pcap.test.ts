import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readCapture } from '../src/pcap.js';
import { analyzeCapture } from '../src/analyze.js';

const directories: string[] = [];

async function createCapture(buffer: Buffer): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'packetlens-'));
  directories.push(directory);
  const path = join(directory, 'sample.pcap');
  await writeFile(path, buffer);
  return path;
}

function makeTcpPacket(source: [number, number, number, number], destination: [number, number, number, number], sourcePort: number, destinationPort: number, flags: number): Buffer {
  const packet = Buffer.alloc(14 + 20 + 20);
  packet[12] = 0x08;
  packet[13] = 0x00;
  const ip = 14;
  packet[ip] = 0x45;
  packet.writeUInt16BE(40, ip + 2);
  packet[ip + 8] = 64;
  packet[ip + 9] = 6;
  source.forEach((value, index) => packet[ip + 12 + index] = value);
  destination.forEach((value, index) => packet[ip + 16 + index] = value);
  const tcp = ip + 20;
  packet.writeUInt16BE(sourcePort, tcp);
  packet.writeUInt16BE(destinationPort, tcp + 2);
  packet[tcp + 12] = 0x50;
  packet[tcp + 13] = flags;
  return packet;
}

function makePcap(packets: Buffer[]): Buffer {
  const header = Buffer.alloc(24);
  header.write('d4c3b2a1', 0, 'hex');
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const records = packets.map((packet, index) => {
    const record = Buffer.alloc(16);
    record.writeUInt32LE(1 + index, 0);
    record.writeUInt32LE(0, 4);
    record.writeUInt32LE(packet.length, 8);
    record.writeUInt32LE(packet.length, 12);
    return Buffer.concat([record, packet]);
  });
  return Buffer.concat([header, ...records]);
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

describe('PCAP decoding', () => {
  it('decodes IPv4 TCP endpoints, ports, flags and timestamps', async () => {
    const packet = makeTcpPacket([192, 0, 2, 10], [198, 51, 100, 20], 51234, 443, 0x12);
    const result = await readCapture(await createCapture(makePcap([packet])));
    expect(result.format).toBe('pcap');
    expect(result.packets).toHaveLength(1);
    expect(result.packets[0]).toMatchObject({ source: '192.0.2.10', destination: '198.51.100.20', sourcePort: 51234, destinationPort: 443, protocol: 'TCP', tcpFlags: ['SYN', 'ACK'], timestamp: 1 });
  });

  it('rejects truncated packet data', async () => {
    const packet = makeTcpPacket([192, 0, 2, 10], [198, 51, 100, 20], 1234, 80, 2);
    const capture = makePcap([packet]).subarray(0, 24 + 16 + 10);
    await expect(readCapture(await createCapture(capture))).rejects.toThrow('Truncated packet data');
  });

  it('reports port-sweep heuristics with evidence', () => {
    const packets = Array.from({ length: 22 }, (_, index) => ({ timestamp: index, capturedLength: 54, originalLength: 54, source: '192.0.2.8', destination: '198.51.100.9', sourcePort: 40000, destinationPort: 1000 + index, protocol: 'TCP' as const, networkProtocol: 'IPv4' as const, tcpFlags: ['SYN'] }));
    const result = analyzeCapture('synthetic.pcap', 'pcap', packets);
    expect(result.findings[0]).toMatchObject({ id: 'tcp-port-sweep', severity: 'medium', packetCount: 22 });
    expect(result.conversations[0]?.packets).toBe(22);
  });
});
