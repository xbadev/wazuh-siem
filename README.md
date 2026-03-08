# Wazuh SIEM — Home Lab

Hands-on SIEM deployment and security monitoring using Wazuh in a virtualized lab environment.

## Labs

| # | Lab | Description |
|---|-----|-------------|
| 01 | [Setup & Deployment](01-setup-and-deployment/) | Installed Wazuh server, deployed agents to Ubuntu and Windows endpoints, configured firewall rules, and resolved service boot issues. |
| 02 | [SSH Brute Force Detection](02-ssh-bruteforce-detection/) | Simulated SSH brute force from Kali, analyzed Wazuh alerts mapped to MITRE ATT&CK, and configured active response to automatically block attackers. |
| 03 | [RDP Brute Force Detection](03-rdp-bruteforce-detection/) | Simulated RDP brute force against Windows endpoint, analyzed Windows Event Log alerts, and compared cross-platform detection with SSH. |

## What's Next

- File integrity monitoring (FIM) across endpoints
