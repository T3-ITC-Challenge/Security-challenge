# ITC Challenge - Penetration Test Report

## Team Information
- **Team:** TEAM 3  
- **Category:** Security  
- **Date:** 23/03/2025 - 15:40  
- **Author:** Oumarou Azahidou Mahamadou  

---

## 📌 Identified Security Issues

### 🔹 1. Exposed Credentials via FTP/HTTP
- **Leaked credentials:**  
  - `Youcef Sahraoui: 123456789`  
  - `Admin: ftp2025`  
- **Detected Attacks:**  
  - Malformed DNS request (`Opcode 12`)  
  - SSH brute-force attempt  
- **Critical Data Leak:**  
  - `accounts.txt` file transferred via FTP (containing user credentials in plaintext).  

### 🔹 2. FTP Data Exposure
- **Exposed commands:**  
  ```plaintext
  USER admin
  PASS ftp2025
  STOR accounts.txt
  ```  
  - ⚠️ *Risk:* Unencrypted passwords transmitted in plaintext pose a severe security threat.

### 🔹 3. HTTP Credential Leak
- **Intercepted HTTP request:**  
  ```plaintext
  POST /login HTTP/1.1
  Host: target.com
  User=youcef.sahraoui&Pass=pass123
  ```  
  - 🔥 *Vulnerability:* Session hijacking possible via BurpSuite.

### 🔹 4. Malformed DNS Packets
- **Detected anomaly:**  
  ```plaintext
  Unknown operation (12) towards 8.8.8.8
  ```  
  - 🛑 *Technical details:*  
    - `Opcode: 12` (Potential exfiltration vector)
    - `Transaction ID: 0x5175` (Decoded using Python3)

### 🔹 5. Attack Attempts Identified

| 🌐 Domain               | 📍 Source IP        | ⏱️ Timestamp  | 🔄 Frequency | ⚠️ Risk Level |
|----------------------|-----------------|------------|------------|------------|
| www.youtube.com     | 192.168.1.30    | 0.002146   | 5x         | Bandwidth abuse |
| www.facebook.com    | 192.168.82.86   | 0.001984   | 3x         | Social Engineering |
| www.wikipedia.org   | 192.168.241.11  | 0.002304   | 2x         | Low risk |

- **Critical Data Found:**  
  - 📞 **Phone Number:** `456123789`

---

## 🚨 MITM Attack - SYN Flood Attempt

### 🛠️ 1. Attack Code (C Language)
```c
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include <thc-ipv4.h>

void help(char* itc_challenge){
    printf("%s %s (c) 2025 by %s %s, itc_challenge, 01, azcbs, RESOURCE);
    printf("Syntax: %s [ -i microseconds ] interface victim-ip [multicast-network-address]\n\n", itc-challenge);
    printf("Smurf the target with ICMP echo replies.\n");
    exit(-1);
}

int main(int argc, char *argv[]){
    unsigned char *pkt = NULL, buf[16], fakemac[7] = "\x00\x00\xde\xad\xbe\xef";
    unsigned char *multicast6, *victim6;
    int i, pkt_len = 0, msec = 0;
    char *interface;
    int rawmode = 0;
}
```

---

## 🔓 SSH Brute-Force Evidence
- **Detected Pattern:**  
  - Multiple SSH login attempts from `192.168.1.39` targeting various ports.
- **Weak Password Usage:**  
  - Admin credentials: `secureSSH!`

### 🔎 1. DNS Tunneling Suspicion
- **Suspicious DNS Flows:**  
  - **Number of abnormal DNS packets:** `20`
  - **Target server:** `8.8.8.8` (*Potential C2 server disguising exfiltration*).

---

## 🔑 Extracted Sensitive Data

| 🆔 User                | 🔐 Password     | 📌 Source |
|---------------------|-------------|--------|
| Youcef Sahraoui    | 123456789    | FTP    |
| Admin              | ftp2025      | FTP    |
| Yousra Araoubia    | ramadan2025  | DNS    |

---

## 🚀 Key Findings
- **Encryption Key Found:** `0x5175 == JBOO` (Used in XOR encryption)

---

## 🛡️ Recommendations

| ⚠️ Vulnerability        | ✅ Solution                  | 🛠️ Recommended Tool |
|----------------------|--------------------------|------------------|
| Unsecured FTP       | Migrate to SFTP/SCP       | vsftpd + SSL    |
| Malformed DNS       | Block non-standard requests | Snort Rule 3  |
| Weak Passwords      | Enforce strong policies   | Fail2Ban        |
| Exposed Services    | Restrict access, audit logs | IPTables       |

### 📌 Additional Measures:
- Isolate exposed FTP/SSH servers.
- Conduct security audits on `admin` user logs.
- Implement network segmentation to prevent lateral movement.

---

**🔚 End of Report**

