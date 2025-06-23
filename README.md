# 🕵️‍♂️ Network Attack Detection Using PCAP Files

This project investigates real-world network attack traffic by analyzing `.pcap` files using tools like **Wireshark**, **Zeek**, and **CyberChef**. It demonstrates how to detect and document various types of attacks, extract Indicators of Compromise (IOCs), decode payloads, and map them to the **MITRE ATT&CK** framework.

---

## 🎯 Project Goals

- Perform traffic analysis on various attack PCAPs
- Detect network-based attack patterns and techniques
- Extract IOCs like IPs, domains, and payloads
- Decode embedded data (e.g., base64 in DNS queries)
- Practice using Wireshark filters and Zeek logs
- Map attacks to the MITRE ATT&CK framework

---

## 🧰 Tools Used

- [Wireshark](https://www.wireshark.org/)
- [Zeek](https://zeek.org/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- Command-line tools (`base64`, `strings`)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## 📁 Repository Structure

```bash
pcap-attack-analysis/
├── analysis/         # Written analysis of each attack
│   └── dns_tunneling.md
│   └── ...
│
├── pcaps/            # PCAP files being analyzed
│   └── dns_tunneling.pcapng
│   └── ...
│
├── threats/          # IOC files, decoded data, filters
│   └── dns_tunneling_iocs.txt
│   └── ...
│
├── images/           # Screenshots from Wireshark/Zeek
│   └── dns_tunneling_packet_view.png
│
├── references.md     # Useful links, filters, docs
└── README.md         # This project overview


---

## 📊 Analyzed Attacks

| Attack Type        | Description                             | MITRE Technique | Status |
|--------------------|-----------------------------------------|------------------|--------|
| DNS Tunneling      | Covert exfiltration via DNS TXT records | T1071.004        | ✅ Done |
| Nmap Xmas Scan     | Stealth scanning via unusual TCP flags  | T1046            | 🔄 Coming Soon |
| ARP Spoofing       | MITM via forged ARP replies             | T1557.002        | 🔄 Coming Soon |
| ICMP Smurf Attack  | DoS using broadcast ICMP echo requests  | T1499            | 🔄 Coming Soon |
| TCP Hijacking      | Hijacking TCP sessions                  | T1020            | 🔄 Coming Soon |

🔍 Full analysis available in the [`analysis/`](./analysis) folder.

---

## ✅ Completed Analysis: DNS Tunneling

- PCAP: [`dns_tunneling.pcapng`](./pcaps/dns_tunneling.pcapng)
- Report: [`dns_tunneling.md`](./analysis/dns_tunneling.md)
- IOCs: [`dns_tunneling_iocs.txt`](./threats/dns_tunneling_iocs.txt)
- Screenshot: ![View](./images/dns_tunneling_packet_view.png)

> Malicious DNS TXT queries were used to encode and exfiltrate data such as `admin:password`, decoded from base64 strings embedded in subdomains.

---

## 📚 References

See [`references.md`](./references.md) for:
- Wireshark filters
- Zeek examples
- MITRE links
- Tools and learning resources

---

## 🧠 What I Learned

> This project gave me practical experience in packet analysis, threat detection, and network security. I improved my skills in Wireshark, decoding encoded payloads, identifying malicious patterns, and understanding attacker behavior through real-world packet captures.

---

## 🚀 Next Steps

- Add more attack types (Nmap, ARP Spoofing, etc.)
- Automate IOC extraction using scripts
- Try replaying PCAPs in a lab for live analysis

---

Feel free to **star** ⭐ this repo if it helps you learn PCAP analysis!


