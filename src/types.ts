export type TransportProtocol = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'OTHER';

export interface PacketRecord {
  timestamp: number;
  capturedLength: number;
  originalLength: number;
  source: string;
  destination: string;
  sourcePort: number | null;
  destinationPort: number | null;
  protocol: TransportProtocol;
  networkProtocol: 'IPv4' | 'IPv6' | 'ARP' | 'OTHER';
  tcpFlags: string[];
}

export interface ConversationRecord {
  source: string;
  destination: string;
  protocol: TransportProtocol;
  packets: number;
  bytes: number;
  firstSeen: number;
  lastSeen: number;
}

export interface SecurityFinding {
  id: string;
  severity: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  evidence: string;
  packetCount: number;
}

export interface CaptureAnalysis {
  file: string;
  format: 'pcap' | 'pcapng';
  packets: number;
  capturedBytes: number;
  protocols: Record<string, number>;
  hosts: Array<{ address: string; packets: number; bytes: number }>;
  conversations: ConversationRecord[];
  findings: SecurityFinding[];
  packetRecords: PacketRecord[];
}
