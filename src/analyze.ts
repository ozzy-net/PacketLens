import type { CaptureAnalysis, ConversationRecord, PacketRecord, SecurityFinding } from './types.js';

function sortByCount<T extends { packets: number }>(items: T[]): T[] {
  return items.sort((a, b) => b.packets - a.packets);
}

function inspectTraffic(packets: PacketRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const synOnly = packets.filter(packet => packet.protocol === 'TCP' && packet.tcpFlags.includes('SYN') && !packet.tcpFlags.includes('ACK'));
  const destinations = new Map<string, Set<number>>();
  for (const packet of synOnly) {
    if (packet.destinationPort === null) continue;
    const ports = destinations.get(packet.source) ?? new Set<number>();
    ports.add(packet.destinationPort);
    destinations.set(packet.source, ports);
  }
  for (const [source, ports] of destinations) {
    if (ports.size >= 20) findings.push({ id: 'tcp-port-sweep', severity: ports.size >= 100 ? 'high' : 'medium', title: 'Possible TCP port sweep', description: 'One source sent SYN packets to many distinct destination ports.', evidence: `${source} contacted ${ports.size} distinct TCP destination ports`, packetCount: synOnly.filter(packet => packet.source === source).length });
  }
  const dns = packets.filter(packet => packet.protocol === 'UDP' && (packet.sourcePort === 53 || packet.destinationPort === 53));
  if (dns.length >= 500) findings.push({ id: 'dns-volume', severity: 'low', title: 'High DNS packet volume', description: 'The capture contains a large number of UDP packets using port 53.', evidence: `${dns.length} UDP packets use source or destination port 53`, packetCount: dns.length });
  const cleartext = packets.filter(packet => packet.protocol === 'TCP' && [21, 23, 80, 110, 143, 8080].includes(packet.sourcePort ?? -1) || packet.protocol === 'TCP' && [21, 23, 80, 110, 143, 8080].includes(packet.destinationPort ?? -1));
  if (cleartext.length > 0) findings.push({ id: 'cleartext-service', severity: 'low', title: 'Potential cleartext service traffic', description: 'Traffic uses a port commonly associated with a service that may transmit data without transport encryption. Port numbers alone do not prove that payloads are cleartext.', evidence: `${cleartext.length} TCP packets match common HTTP, FTP, Telnet, POP3, or IMAP ports`, packetCount: cleartext.length });
  return findings;
}

export function analyzeCapture(file: string, format: 'pcap' | 'pcapng', packets: PacketRecord[]): CaptureAnalysis {
  const protocols: Record<string, number> = {};
  const hosts = new Map<string, { address: string; packets: number; bytes: number }>();
  const conversations = new Map<string, ConversationRecord>();
  let capturedBytes = 0;
  for (const packet of packets) {
    protocols[packet.protocol] = (protocols[packet.protocol] ?? 0) + 1;
    capturedBytes += packet.capturedLength;
    for (const address of new Set([packet.source, packet.destination])) {
      if (address === 'unknown') continue;
      const host = hosts.get(address) ?? { address, packets: 0, bytes: 0 };
      host.packets++;
      host.bytes += packet.capturedLength;
      hosts.set(address, host);
    }
    const endpoints = [`${packet.source}:${packet.sourcePort ?? ''}`, `${packet.destination}:${packet.destinationPort ?? ''}`].sort();
    const key = `${packet.protocol}|${endpoints[0]}|${endpoints[1]}`;
    const conversation = conversations.get(key) ?? { source: endpoints[0]!, destination: endpoints[1]!, protocol: packet.protocol, packets: 0, bytes: 0, firstSeen: packet.timestamp, lastSeen: packet.timestamp };
    conversation.packets++;
    conversation.bytes += packet.capturedLength;
    conversation.firstSeen = Math.min(conversation.firstSeen, packet.timestamp);
    conversation.lastSeen = Math.max(conversation.lastSeen, packet.timestamp);
    conversations.set(key, conversation);
  }
  return { file, format, packets: packets.length, capturedBytes, protocols: Object.fromEntries(Object.entries(protocols).sort((a, b) => b[1] - a[1])), hosts: sortByCount([...hosts.values()]), conversations: [...conversations.values()].sort((a, b) => b.bytes - a.bytes), findings: inspectTraffic(packets), packetRecords: packets };
}
