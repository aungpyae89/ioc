# Linux VM Cryptomining Incident – Public Threat Intelligence Report

Last Updated: 2025-09-25

Status: Public Disclosure / Research Contribution

This repository contains publicly shareable threat intelligence related to a confirmed Linux VM compromise that resulted in the deployment of an XMRig Monero cryptominer.
The objective of this report is to support the security community by providing

Indicators of Compromise (IOCs)

Timeline of attacker activity

Malware artifacts (scripts, downloader URLs, wallets)

MITRE ATT&CK technique mappings

Important Note : No organization names, internal identifiers, or sensitive commercial information are included.


A Linux virtual machine hosted in a cloud environment was compromised through unauthorized console access (VNC).
Using this access, the attacker obtained root privileges, downloaded multiple malicious scripts, deployed the XMRig cryptominer, and executed anti-forensic actions including history clearing and log removal.

The host was eventually rebuilt from a clean image due to kernel-level tampering.

## Attacker Activity Timeline (MMT UTC+6:30)

| Timestamp                          | Activity                                               |
| ---------------------------------- | ------------------------------------------------------ |
| 2025-09-17 05:06:06                | First download of `main.zip` from 116.203.186.178      |
| 2025-09-17 05:07:18 / 05:07:31     | Repeated download attempts of `main.zip`               |
| 2025-09-17 05:07:41                | GitHub variant of `main.zip` downloaded                |
| 2025-09-17 16:06                   | First detection triggered (root password change alert) |
| 2025-09-17 16:09–16:10             | `auto.sh` downloaded from 91.237.1.223                 |
| 2025-09-17 16:42:28                | `xm.sh` (miner deployment script) downloaded           |
| Post-compromise                    | XMRig miner executed, connecting to *hashvault.pro*    |
| After detection                    | Host fully rebuilt; mining activity terminated         |


## Indicators of Compromise (Full CSV Included)

You can find the full IOC list in -  public_ioc_crytominer.csv

## Downloader Servers

116.203.186.178

91.237.1.223

## Malicious URLs

https://116.203.186.178/DgpO3

https://116.203.186.178/NcvdW

https://raw.githubusercontent.com/updateservice/rp/main/main.zip

https://91.237.1.223/auto.sh

https://91.237.1.223/xm.sh

Mining Pool

hashvault.pro

## Artifacts Found on Host

main.zip

auto.sh

xm.sh

xmrig.json with Monero wallet configuration

## Attacker Tooling & Behavior
# Malware Components
| File           | Purpose                                      |
| -------------- | -------------------------------------------- |
| `main.zip`     | Primary payload containing scripts and miner |
| `auto.sh`      | Initial execution and downloader script      |
| `xm.sh`        | Miner loader + persistence helper            |
| `xmrig` binary | Monero mining payload                        |
| `xmrig.json`   | Miner config (wallet + pool)                 |

## Observed Behaviors

Remote console (VNC) used as access vector

Privilege escalation (root)

Downloading and executing malicious scripts

Log wiping and shell history clearing

Resource hijacking via XMRig

Persistence via modified scripts

## MITRE ATT&CK Mapping

| Technique ID | Technique Name     | Description                           |
| ------------ | ------------------ | ------------------------------------- |
| T1496        | Resource Hijacking | XMRig cryptomining                    |
| T1078        | Valid Accounts     | Root-level login after console access |
| T1021        | Remote Services    | VNC console access path               |
| T1070        | Indicator Removal  | Log & shell history deletion          |
| T1083        | File Discovery     | Reconnaissance by scripts             |

/public_ioc_crytominer.csv        (Full IOC list)
/main.zip.enc             (Script samples, filenames, metadata)
/README.md              (This file)

## ⚠️ Malware Sample Notice

This repository contains an encrypted malware sample (`main.zip.enc`) for 
educational, research, and defensive security purposes only. 

The archive is password-protected with the standard malware research password.

Password: infected

Do NOT execute the contents unless you are trained and operating in a safe, 
isolated analysis environment (air-gapped VM, no network, no production access).

This publication follows common practices used by MalwareBazaar, HybridAnalysis,
and other malware research-sharing communities.

📝 License
This documentation and artifacts are published under [CC BY 4.0] for global defender use.
