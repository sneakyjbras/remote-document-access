## Setup ##
- Linux kali 4.18.0-kali3-amd64 #1 SMP Debian 4.18.20-2kali2 (2018-11-30) x86_64 GNU/Linux  
- OpenSSL 1.1.1a 20 Nov 2018  
- Python 2.7.15+ (default, Aug 31 2018, 11:56:52)  
  
## Install dependencies ##
Steps you should take:  
`apt update`  
`apt install python python-pip build-essential libssl-dev libffi-dev python-dev`  
`apt install openssl`  
If needed, follow this installer to install openssl manually: https://websiteforstudents.com/manually-install-the-latest-openssl-toolkit-on-ubuntu-16-04-18-04-lts/ and remember to download the tar.gz from "https://www.openssl.org/source/openssl-1.1.1a.tar.gz", so you can download the used version "1.1.1a", and substitute 1.1.1 for 1.1.1a in all steps.  
`chmod +x server.py *.sh`  
`pip install -r requirements.txt`  
  
## First time deployment ##
`./CA_SERVER_CERTS_KEYPAIRS.sh` and then copy the trusted ca cert to the client app  
  
Finally, run it:
`python server.py`  
