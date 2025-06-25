# 🛑 ARP Spoofing - Analysis

## 📂 PCAP File
`pcaps/ARP_Spoof.pcapng`

## 🔍 Objective
Analyze ARP spoofing attack where an attacker sends forged ARP replies to intercept traffic between two hosts.

---

## 🛠 Tools Used
- Wireshark
- CyberChef (optional for payloads)
- MITRE ATT&CK

---

## 🔎 Key Observations in PCAP

- Multiple unsolicited ARP replies (gratuitous ARPs)
- One machine repeatedly claims to own 192.168.1.1 (default gateway)
- Victim starts sending data to attacker's MAC
- Packets from victim go to attacker’s MAC → then attacker relays (or drops)

---

## TCPDump
sudo apt isntall tcpdump-y
sudo tcpdump -i eth0 -w filename.pcapng
## 🧪 Wireshark Filters Used

```wireshark
arp
arp.opcode == 1
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba
arp.duplicate-address-detected && arp.opcode == 2
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
