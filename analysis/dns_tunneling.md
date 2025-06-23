# DNS Tunneling - PCAP Analysis

## 🔍 Objective
Detect potential DNS tunneling activity used for data exfiltration by inspecting DNS TXT records and patterns.

## 📂 PCAP File
`pcaps/dns_tunneling.pcapng`

## 🛠 Tools Used
- Wireshark
- (Optional: Zeek for dns.log analysis)

## 🔎 Key Observations
- A high volume of **TXT DNS queries** from one source IP
- Long, encoded-looking subdomain names in the TXT queries
- Queries are directed to a single suspicious domain (e.g., `tunnel.attacker-domain.xyz`)
- Query intervals appear consistent (e.g., every 1–2 seconds)

## 🧪 Wireshark Filters Used

```wireshark
dns.qry.type == 16
dns.qry.name contains "xyz"
ip.src == x.x.x.x  # Replace with actual source IP


## ⚠️ Indicators of Compromise (IOCs)
- Domain: `tunnel.attacker-domain.xyz`
- Record Type: TXT (dns.qry.type == 16)
- Pattern: Long subdomains with base64/hex strings
- Frequency: Repeated every ~2 seconds
- Source IP: 192.168.1.100 (example — replace with actual)

