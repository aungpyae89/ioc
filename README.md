# Linux VM Cryptomining Incident – Public Threat Intelligence Report

Last Updated: 2025-09-25

Status: Public Disclosure / Research Contribution

This repository contains publicly shareable threat intelligence related to a confirmed Linux VM compromise that resulted in the deployment of an XMRig Monero cryptominer.
The objective of this report is to support the security community by providing

-Indicators of Compromise (IOCs)

-Timeline of attacker activity

-Malware artifacts (scripts, downloader URLs, wallets)

-MITRE ATT&CK technique mappings

## Important Note: No organization names, internal identifiers, or sensitive commercial information are included.

[Descriptions]
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

Mining Pool Web URL 

-hashvault.pro

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
/linux-crypto-mining-stix-2.json  (STIX 2.0 Json File)
/README.md              (This file)

## Analysis inside main.zip file and MITRE ATT&CK Mapping

🔍 Overview

Attackers commonly deploy a collection of bash scripts (f.sh, k.sh, d.sh, logg.sh) to

Create unauthorized root-level accounts

Hijack execution flow via library preload

Hide processes and impair defenses

Stop competing miners and security tools

Maintain persistence via cron

Auto-select the best mining configuration

Execute XMRig for cryptojacking

All techniques below are aligned to MITRE ATT&CK v14.

| Script | Line / Action | Technique ID | Technique Name | Details |
|--------|----------------|--------------|----------------|---------|
| f.sh | `useradd --non-unique --uid 0 system` | T1136.001 | Create Account: Local Account | Creates a root-level (UID 0) user named **system** for backdooring. |
| f.sh | `mv uv system.so /usr/local/lib/... && echo '/usr/local/lib/system.so' | tee -a /etc/ld.so.preload` | T1574.006 | Hijack Execution Flow: Dynamic-link Library Hijacking | Injects a malicious shared object into preload list to hijack system binaries. |
| f.sh | `echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab` + `mount -o remount,rw,hidepid=2 /proc` | T1562.004 | Impair Defenses: Disable or Modify System Firewall | Hides system processes from other users; stealth technique. |
| f.sh | `systemctl mask -f ctrl-alt-del.target` | T1562.001 | Impair Defenses: Disable or Modify Tools | Blocks Ctrl+Alt+Del kernel reboot path to prevent manual recovery. |
| f.sh | GRUB password modifications | T1078.004 | Valid Accounts: Local Accounts | Sets GRUB bootloader password for unauthorized boot-time access. |
| logg.sh | `crontab -l | grep -q ... && echo '* * * * * /mnt/loggd.sh'` | T1053.003 | Scheduled Task/Job: Cron | Adds recurring cron job for persistence. |
| k.sh | `ufw deny 22`, killing processes, stopping services | T1489 | Service Stop | Disables security tools / competing miners to protect attacker resources. |
| k.sh | `ls -A /root | grep -v -E ... | xargs -I {} rm -rf /root/{}` | T1070.004 | Indicator Removal on Host | Deletes evidence/logs inside `/root` directory. |
| d.sh | `rm -rf config.json; mv config[x/h/z].json config.json` | T1083 | File and Directory Discovery | Auto-selects appropriate miner config based on system characteristics. |
| All | XMRig execution | T1496 | Resource Hijacking | Final objective: launch XMRig for illicit mining. |

## SHA256 For Files 
787a5e2200df8e37353b1d577e1ece398fbff83350091bfbc9a76e7e6ceceb3c  main.zip.enc
726fa5a147267abb9e8be400304697a9f65bf0d8bc48914f135bb40e011d7567  public_ioc_crytominer.csv
bce5327a2b51f34368f82566a659c0d00d01a93616a2b5ce40c350f9e8d7da7d  linux-crypto-mining-stix-2.json

## ⚠️ Malware Sample Notice

This repository contains an encrypted malware sample (`main.zip.enc`) for 
educational, research, and defensive security purposes only. 

The archive is password-protected with the standard malware research password.

Password: infected

Do NOT execute the contents unless you are trained and operating in a safe, 
isolated analysis environment (air-gapped VM, no network, no production access).

This publication follows common practices used by MalwareBazaar, HybridAnalysis,
and other malware research-sharing communities.

## 📝 License
This documentation and artifacts are published under [CC BY 4.0] for global defender use.
