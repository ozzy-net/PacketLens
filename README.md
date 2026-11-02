# PacketLens

PacketLens is a lightweight command-line analyser for PCAP and PCAPNG captures. It extracts packet metadata, groups traffic into conversations, summarises hosts and protocols, and reports a small set of explainable traffic heuristics.

## Features

- Reads classic PCAP files with microsecond or nanosecond timestamps
- Reads PCAPNG section, interface, and enhanced packet blocks
- Decodes Ethernet, VLAN-tagged Ethernet, raw IPv4, and raw IPv6 frames
- Summarises transport protocols, hosts, and conversations
- Identifies possible TCP port sweeps, high DNS packet volume, and traffic using commonly cleartext service ports
- Filters analysis by protocol or host
- Writes JSON reports for automation
- Runs on Node.js 20 or newer

## Requirements

- Node.js 20+
- npm

## Install

```sh
git clone https://github.com/ozzy-net/PacketLens.git
cd PacketLens
npm install
npm run build
```

## Usage

Run directly during development:

```sh
npm start -- capture.pcap
```

Build and run the compiled CLI:

```sh
node dist/cli.js capture.pcap
```

Show the available options:

```sh
npm start -- --help
```

Filter to TCP packets involving a specific host and save a JSON report:

```sh
npm start -- capture.pcap --protocol TCP --host 192.0.2.10 --json report.json
```

Write JSON to standard output:

```sh
npm start -- capture.pcap --json -
```

## Findings

PacketLens currently includes simple heuristics for possible TCP port sweeps, high UDP DNS packet volume, and traffic using ports commonly associated with cleartext services. Findings include evidence and packet counts so that analysts can review why a heuristic matched.

These signals are not proof of malicious activity. Port numbers do not establish what application protocol was used, and a capture with no findings is not proof that a network is safe.

## Supported traffic

PacketLens currently decodes Ethernet and raw IP link types. It extracts IPv4 and IPv6 endpoints, TCP and UDP ports, and TCP flags. IPv6 extension headers and deeper application-layer protocol parsing are not currently implemented. Unsupported link types remain visible as unknown packet records rather than being decoded incorrectly.

## Development

```sh
npm install
npm run build
npm test
npm run check
```

The test suite builds synthetic captures so it can run without private or real-world packet data.

## Licence

MIT. See [LICENSE](LICENSE).
