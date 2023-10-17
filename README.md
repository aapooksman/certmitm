# certmitm

```
               _             _ _               _                                     
              | |           (_) |             | |                                    
  ___ ___ _ __| |_ _ __ ___  _| |_ _ __ ___   | |__  _   _    __ _  __ _ _ __   ___  
 / __/ _ \ '__| __| '_ ` _ \| | __| '_ ` _ \  | '_ \| | | |  / _` |/ _` | '_ \ / _ \ 
| (_|  __/ |  | |_| | | | | | | |_| | | | | | | |_) | |_| | | (_| | (_| | |_) | (_) |
 \___\___|_|   \__|_| |_| |_|_|\__|_| |_| |_| |_.__/ \__, |  \__,_|\__,_| .__/ \___/ 
                                                      __/ |             | |          
                                                     |___/              |_|          

```

A tool for testing for certificate validation vulnerabilities of TLS connections made by a client device or an application.

Created by Aapo Oksman - https://github.com/AapoOksman/certmitm - MIT License

Published in DEF CON 31 on August 11 2023

[YouTube: DEF CON 31 - certmitm: automatic exploitation of TLS certificate validation vulnerabilities - Aapo Oksman](https://www.youtube.com/watch?v=w_l2q_Gyqfo)

[DEF CON 31 certmitm Slides.pdf](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Aapo%20Oksman%20-%20certmitm%20automatic%20exploitation%20of%20TLS%20certificate%20validation%20vulnerabilities.pdf)

[DEF CON 31 certmitm Demo.mp4](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Aapo%20Oksman%20-%20certmitm%20automatic%20exploitation%20of%20TLS%20certificate%20validation%20vulnerabilities-demo.mp4)

## Installation

certmitm has been tested on Debian 11 and Debian 12. It should work on Linux with Python 3.10 and up

Install required python packages with

```
pip install -r requirements.txt
```

Obtain real certificates such as a Let's Encrypt certificate and save them to [real_certs](real_certs)

## Usage

First you need to intercept TLS connections. The easies way for this is to configure the computer running certmitm to act as a router for other devices in the network.

For example:

1. Start a DHCP/DNS server

```
sudo ip addr add 10.0.0.1/24 dev eth0
sudo dnsmasq --no-daemon --interface eth0 --dhcp-range=10.0.0.100,10.0.0.200 --log-dhcp --log-queries --bind-interfaces -C /dev/null
```

2. Intercept TLS connections from the clients and redirect other connections to the internet through the WLAN interface

```
sudo iptables -A INPUT -i eth0 -j ACCEPT
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 9900
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
```

3. Start certmitm

```
python3 certmitm.py --listen 9900 --workdir testing --verbose --show-data
```

4. Connect clients to the network and start applications. Note that you might need to retry running the applications a couple of times while the tests fail.

## Hall of fame

List of publicly disclosed vulnerabilities found with certmitm. Open an issue if you have found a vulnerability with certmitm and want to be included.

| Author        | Product       | Details     | CVE |
| ------------- | ------------- | ----------- | --- |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Microsoft Azure Java SDK | [Microsoft advisory](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-16971) | CVE-2020-16971 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Microsoft Azure C SDK | [Microsoft advisory](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-17002) | CVE-2020-17002 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Disk-o-cloud | [HackerOne report](https://hackerone.com/reports/1026893) |  |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Apple iOS App Store | [Apple security update](https://support.apple.com/en-us/HT212317) | CVE-2021-1837 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Microsoft Intune | [Microsoft advisory](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-31980) | CVE-2021-31980 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Acronis True Image | [Acronis advisory](https://security-advisory.acronis.com/updates/UPD-2103-e974-184f), [HackerOne report](https://hackerone.com/reports/1056144) | CVE-2021-32581 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Microsoft Windows Authentication | [Microsoft advisory](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2022-26913) | CVE-2022-26913 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Mattermost iOS | [Mattermost advisory MMSA-2023-00220](https://mattermost.com/security-updates/) | CVE-2023-3615 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Microsoft Windows Enroll Engine | [Microsoft advisory](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2023-28226) | CVE-2023-28226 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Samsung Email for Android | [Samsung advisory SVE-2023-1004](https://security.samsungmobile.com/serviceWeb.smsb) | CVE-2023-30729 |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Apple Books for iOS, macOS and watchOS | [macOS Sonoma 14 security updates](https://support.apple.com/HT213940), [iOS 17 and iPadOS 17 security updates](https://support.apple.com/HT213938), [watchOS 10 security updates](https://support.apple.com/HT213937) |  |
| Aapo Oksman [[in]](https://www.linkedin.com/in/AapoOksman/) [[X]](https://twitter.com/AapoOksman)  | Line iOS | [HackerOne report](https://hackerone.com/reports/2106827) | CVE-2023-5554 |
