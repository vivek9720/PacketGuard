# PacketGuard

PacketGuard is an offline C++17 toolkit for inspecting local defensive security artifacts. It helps security engineers and system administrators review packet captures, indicator files, IDS-style signatures, firewall exports, and lightweight policy files without sending data to a service.

## Use Cases

- Summarize PCAP captures and extract IPv4, TCP, UDP, and DNS metadata.
- Normalize IOC files containing IPv4 addresses, CIDR ranges, domains, URLs, and common file hashes.
- Match local packet metadata against allowlists, blocklists, and indicator bundles.
- Inspect IDS signatures written in a practical Snort/Suricata-like rule subset.
- Audit iptables-style and nftables-style firewall exports for duplicates, broad rules, and ordering risks.
- Parse small local INI, JSON-like, and CSV policy files for review inventories.

## Supported Artifacts

- Classic PCAP files with Ethernet link-layer frames.
- Ethernet, IPv4, TCP, UDP, and DNS packet data.
- IOC lists with optional role, severity, confidence, and key/value attributes.
- IDS signatures with action, protocol, source, destination, ports, `msg`, `content`, `sid`, `rev`, and `classtype` fields.
- iptables-style rules and nftables-style rule lines.
- Local policy files using simple INI, CSV, or JSON-style key/value layouts.

## Architecture

- `core`: byte readers, safe slicing, diagnostics, status values, checksums, string helpers, timestamps, IPv4, and CIDR helpers.
- `packet`: PCAP, Ethernet, IPv4, TCP, UDP, DNS decoding, metadata extraction, and summaries.
- `ioc`: indicator parsing, normalization, duplicate detection, allow/block roles, and packet metadata matching.
- `rules`: IDS-style lexer/parser behavior, normalization, validation, duplicate detection, and packet matching helpers.
- `policy`: firewall and policy parsing, ordering analysis, duplicate and shadowed-rule detection, and summaries.
- `tools`: command-line programs that call the reusable library code.

## Build

```bash
cmake -S . -B build
cmake --build build --config Release
```

The project uses only the C++ standard library and performs local file processing only.

## Tests

```bash
ctest --test-dir build --output-on-failure
```

The deterministic tests cover valid and invalid examples across core parsing, packets, IOC handling, IDS rules, and policy auditing.

## CLI Usage

```bash
./build/packetscan capture.pcap
./build/packetscan capture.pcap --ioc indicators.txt --rules signatures.rules
./build/iocmatch indicators.txt capture.pcap
./build/rulecheck signatures.rules --normalize
./build/policyaudit firewall.rules --normalize
```

On multi-config generators, use the executable path under the selected configuration directory, such as `build/Release/packetscan`.

## Developer QA

PacketGuard includes libFuzzer-compatible robustness harnesses for the major parsers:

```bash
mkdir -p out
CXX=clang++ OUT=$PWD/out LIB_FUZZING_ENGINE=-fsanitize=fuzzer \
  CXXFLAGS="-fsanitize=address,undefined -g -O1" \
  bash .clusterfuzzlite/build.sh

out/packet_fuzzer fuzz/corpus/packet_fuzzer -dict=fuzz/dictionary.txt -runs=1000
out/ioc_fuzzer fuzz/corpus/ioc_fuzzer -dict=fuzz/dictionary.txt -runs=1000
out/rules_fuzzer fuzz/corpus/rules_fuzzer -dict=fuzz/dictionary.txt -runs=1000
out/policy_fuzzer fuzz/corpus/policy_fuzzer -dict=fuzz/dictionary.txt -runs=1000
```

The seed corpus contains compact but realistic examples: valid and malformed PCAP captures, IOC lists by type, IDS signatures, and firewall/policy exports. The dictionary contains protocol constants, record names, IOC separators, hash prefixes, IDS keywords, firewall actions, and policy punctuation to help mutation reach structured parser paths.

## Manual Review Checklist

- Confirm new parsers keep bounded reads and report diagnostics instead of throwing for expected malformed input.
- Keep command-line tools deterministic and limited to local files.
- Review new normalization logic against real operational examples before relying on it for enforcement decisions.
- Add focused tests for every accepted artifact variant and every rejected malformed variant.
- Keep third-party code out of the tree unless it is deliberately reviewed and licensed.
- Review rule and policy warnings as triage aids rather than final security decisions.
