# 🚩 Abnormal TCP Flag Behavior - Attack Analysis

## 📂 PCAP File
`pcaps/nmap_syn_scan.pcapng` *(example)*
`pcaps/nmap_null_scan.pcapng`
`pcaps/nmap_ack_scan.pcapng`
`pcaps/nmap_fin_scan.pcapng`
`pcaps/nmap_xmax_scan.pcapng` 
## 🎯 Objective
Too many flags of a kind or kinds - This could show us that scanning is occurring within our network.

The usage of different and unusual flags - Sometimes this could indicate a TCP RST attack, hijacking, or simply some form of control evasion for scanning.

Solo host to multiple ports, or solo host to multiple hosts - Easy enough, we can find scanning as we have done before by noticing where these connections are going from one host. In a lot of cases, we may even need to consider decoy scans and random source attacks.
Analyze different attack patterns using **malformed or excessive TCP flag combinations**. These anomalies deviate from the normal TCP 3-way handshake and indicate scanning, fuzzing, or DoS attempts.

---

## 🔍 Abnormal TCP Flag Patterns

### 1. 🚨 Excessive SYN Flags (SYN Flood / Half-Open Scan)

- **Attack Type**: DoS or SYN scan (e.g., Nmap)
- **Behavior**: Multiple `SYN` packets with no corresponding `ACK`
- **Purpose**: Exhaust server resources or detect open ports
- **Wireshark Filter**:
  ```wireshark
-  tcp

SYN Scans - In these scans the behavior will be as we see, however the attacker will pre-emptively end the handshake with the RST flag.

SYN Stealth Scans - In this case the attacker will attempt to evade detection by only partially completing the TCP handshake.

### 2. NO Flags 

f the port is open - The system will not respond at all since there is no flags.

If the port is closed - The system will respond with an RST packet.

### 3. Too Many ACK's 

If the port is open - The affected machine will either not respond, or will respond with an RST packet.

If the port is closed - The affected machine will respond with an RST packet.

### 4. Excessive FIN's 

If the port is open - Our affected machine simply will not respond.

If the port is closed - Our affected machine will respond with an RST packet.

## 5. Just Too Many Flags 

If the port is open - The affected machine will not respond, or at least it will with an RST packet.

If the port is closed - The affected machine will respond with an RST packet.
