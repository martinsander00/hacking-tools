# Network Packet Interceptor and Injector

## Description
This Python script uses the Scapy library to perform network packet sniffing and manipulation specifically targeting TCP traffic on port 31337. It is designed to intercept TCP packets that contain specific commands (`COMMANDS`, `SECRET`, and `FLAG`), and based on the content of these packets, it injects crafted responses. The main functionalities include:
- **Detecting command packets** to trigger FLAG or SECRET commands.
- **Injecting FLAG commands** immediately upon detecting a packet with the `COMMANDS` content.



## Requirements
- Python 3.x
- Scapy library
- Run redirect_traffic.py before running sniff.py to have traffic incoming to your IP address 

To install Scapy, run:
```bash
pip install scapy

