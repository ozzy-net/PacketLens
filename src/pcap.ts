import { readFile } from 'node:fs/promises';
import type { PacketRecord, TransportProtocol } from './types.js';

interface FrameData {
  timestamp: number;
  capturedLength: number;
  originalLength: number;
  data: Buffer;
  linkType: number;
}

const readU16 = (buffer: Buffer, offset: number, littleEndian: boolean) => littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
const readU32 = (buffer: Buffer, offset: number, littleEndian: boolean) => littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);

function parsePcap(buffer: Buffer): FrameData[] {
  if (buffer.length < 24) throw new Error('PCAP header is incomplete');
  const magic = buffer.subarray(0, 4).toString('hex');
  const formats: Record<string, { little: boolean; scale: number }> = {
    'd4c3b2a1': { little: true, scale: 1_000_000 },
    'a1b2c3d4': { little: false, scale: 1_000_000 },
    '4d3cb2a1': { little: true, scale: 1_000_000_000 },
    'a1b23c4d': { little: false, scale: 1_000_000_000 }
  };
  const format = formats[magic];
  if (!format) throw new Error('Unsupported PCAP magic number');
  const linkType = readU32(buffer, 20, format.little);
  const frames: FrameData[] = [];
  let offset = 24;
  while (offset < buffer.length) {
    if (offset + 16 > buffer.length) throw new Error(`Truncated packet header at byte ${offset}`);
    const seconds = readU32(buffer, offset, format.little);
    const fraction = readU32(buffer, offset + 4, format.little);
    const capturedLength = readU32(buffer, offset + 8, format.little);
    const originalLength = readU32(buffer, offset + 12, format.little);
    offset += 16;
    if (capturedLength > buffer.length - offset) throw new Error(`Truncated packet data at byte ${offset}`);
    frames.push({ timestamp: seconds + fraction / format.scale, capturedLength, originalLength, data: buffer.subarray(offset, offset + capturedLength), linkType });
    offset += capturedLength;
  }
  return frames;
}

function parsePcapng(buffer: Buffer): FrameData[] {
  const frames: FrameData[] = [];
  let offset = 0;
  let little = true;
  let interfaces: Array<{ linkType: number; resolution: number }> = [];
  while (offset + 12 <= buffer.length) {
    const typeBytes = buffer.subarray(offset, offset + 4).toString('hex');
    if (typeBytes === '0a0d0d0a') {
      if (offset + 12 > buffer.length) throw new Error('Truncated PCAPNG section header');
      const bom = buffer.subarray(offset + 8, offset + 12).toString('hex');
      if (bom === '4d3c2b1a') little = true;
      else if (bom === '1a2b3c4d') little = false;
      else throw new Error('Invalid PCAPNG byte-order magic');
      interfaces = [];
    }
    const blockType = typeBytes === '0a0d0d0a' ? 0x0a0d0d0a : readU32(buffer, offset, little);
    const blockLength = readU32(buffer, offset + 4, little);
    if (blockLength < 12 || offset + blockLength > buffer.length || blockLength % 4 !== 0) throw new Error(`Invalid PCAPNG block length at byte ${offset}`);
    const body = offset + 8;
    if (blockType === 1 && blockLength >= 20) {
      const linkType = readU16(buffer, body, little);
      let resolution = 1e-6;
      let option = body + 8;
      const end = offset + blockLength - 4;
      while (option + 4 <= end) {
        const code = readU16(buffer, option, little);
        const length = readU16(buffer, option + 2, little);
        option += 4;
        if (code === 0) break;
        if (option + length > end) break;
        if (code === 9 && length >= 1) {
          const value = buffer[option]!;
          resolution = value & 0x80 ? 1 / (2 ** (value & 0x7f)) : 10 ** -value;
        }
        option += length + ((4 - length % 4) % 4);
      }
      interfaces.push({ linkType, resolution });
    } else if (blockType === 6 && blockLength >= 32) {
      const interfaceId = readU32(buffer, body, little);
      const high = readU32(buffer, body + 4, little);
      const low = readU32(buffer, body + 8, little);
      const capturedLength = readU32(buffer, body + 12, little);
      const originalLength = readU32(buffer, body + 16, little);
      const dataOffset = body + 20;
      const dataEnd = dataOffset + capturedLength;
      if (dataEnd > offset + blockLength - 4) throw new Error(`Truncated PCAPNG packet at byte ${offset}`);
      const iface = interfaces[interfaceId];
      if (iface) {
        const ticks = high * 0x1_0000_0000 + low;
        frames.push({ timestamp: ticks * iface.resolution, capturedLength, originalLength, data: buffer.subarray(dataOffset, dataEnd), linkType: iface.linkType });
      }
    }
    offset += blockLength;
  }
  if (offset !== buffer.length) throw new Error(`Trailing incomplete PCAPNG block at byte ${offset}`);
  return frames;
}

function ipv4(buffer: Buffer, offset: number): string {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

function ipv6(buffer: Buffer, offset: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) groups.push(buffer.readUInt16BE(offset + i * 2).toString(16));
  return groups.join(':');
}

function decodeFrame(frame: FrameData): PacketRecord {
  const fallback: PacketRecord = { timestamp: frame.timestamp, capturedLength: frame.capturedLength, originalLength: frame.originalLength, source: 'unknown', destination: 'unknown', sourcePort: null, destinationPort: null, protocol: 'OTHER', networkProtocol: 'OTHER', tcpFlags: [] };
  let offset = 0;
  let etherType = 0;
  if (frame.linkType === 1) {
    if (frame.data.length < 14) return fallback;
    etherType = frame.data.readUInt16BE(12);
    offset = 14;
    while ([0x8100, 0x88a8, 0x9100].includes(etherType) && frame.data.length >= offset + 4) {
      etherType = frame.data.readUInt16BE(offset + 2);
      offset += 4;
    }
  } else if (frame.linkType === 101) {
    const version = frame.data[0]! >> 4;
    etherType = version === 4 ? 0x0800 : version === 6 ? 0x86dd : 0;
  } else {
    return fallback;
  }
  if (etherType === 0x0806) return { ...fallback, networkProtocol: 'ARP', protocol: 'OTHER' };
  let source = 'unknown';
  let destination = 'unknown';
  let transport = 0;
  let networkProtocol: PacketRecord['networkProtocol'] = 'OTHER';
  if (etherType === 0x0800) {
    if (frame.data.length < offset + 20) return fallback;
    const headerLength = (frame.data[offset]! & 0x0f) * 4;
    if (headerLength < 20 || frame.data.length < offset + headerLength) return fallback;
    source = ipv4(frame.data, offset + 12);
    destination = ipv4(frame.data, offset + 16);
    transport = frame.data[offset + 9]!;
    offset += headerLength;
    networkProtocol = 'IPv4';
  } else if (etherType === 0x86dd) {
    if (frame.data.length < offset + 40) return fallback;
    source = ipv6(frame.data, offset + 8);
    destination = ipv6(frame.data, offset + 24);
    transport = frame.data[offset + 6]!;
    offset += 40;
    networkProtocol = 'IPv6';
  } else {
    return { ...fallback, networkProtocol };
  }
  const protocol: TransportProtocol = transport === 6 ? 'TCP' : transport === 17 ? 'UDP' : transport === 1 ? 'ICMP' : transport === 58 ? 'ICMPv6' : 'OTHER';
  let sourcePort: number | null = null;
  let destinationPort: number | null = null;
  let tcpFlags: string[] = [];
  if ((protocol === 'TCP' || protocol === 'UDP') && frame.data.length >= offset + 4) {
    sourcePort = frame.data.readUInt16BE(offset);
    destinationPort = frame.data.readUInt16BE(offset + 2);
    if (protocol === 'TCP' && frame.data.length >= offset + 14) {
      const bits = frame.data[offset + 13]!;
      tcpFlags = [[0x01, 'FIN'], [0x02, 'SYN'], [0x04, 'RST'], [0x08, 'PSH'], [0x10, 'ACK'], [0x20, 'URG'], [0x40, 'ECE'], [0x80, 'CWR']].filter(([mask]) => (bits & Number(mask)) !== 0).map(([, name]) => String(name));
    }
  }
  return { ...fallback, source, destination, sourcePort, destinationPort, protocol, networkProtocol, tcpFlags };
}

export async function readCapture(path: string): Promise<{ format: 'pcap' | 'pcapng'; packets: PacketRecord[] }> {
  const buffer = await readFile(path);
  if (buffer.length < 4) throw new Error('Capture file is too small');
  const magic = buffer.subarray(0, 4).toString('hex');
  const format = magic === '0a0d0d0a' ? 'pcapng' : 'pcap';
  const frames = format === 'pcapng' ? parsePcapng(buffer) : parsePcap(buffer);
  return { format, packets: frames.map(decodeFrame) };
}
