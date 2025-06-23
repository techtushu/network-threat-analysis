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
- dns


## Bash Command Used
-  echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d 
-  echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d
## ⚠️ Indicators of Compromise (IOCs)
- Domain: `tunnel.attacker-domain.xyz`
- Record Type: TXT (dns)
- Pattern: Long subdomains with base64/hex strings
- Frequency: Repeated every ~2 seconds
- Source IP: 192.168.10.5 

