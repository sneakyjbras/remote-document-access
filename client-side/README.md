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
  
`chmod +x client.py utils/*.sh`  
`pip install -r requirements.txt`  
Extra step for activating argcomplete module:  
`activate-global-python-argcomplete` and restart shell so it takes effect  
Client is now set up.  

## Test it ##
Read client options:  
`python client.py -h`  
`python client.py`  
  
Play with client:  
`python client.py --login davidmatos --list-individualfiles`  
`python client.py --login davidmatos --send-individual myprivatefiles/apresentacao.txt`  
`python client.py --login davidmatos --send-individual myprivatefiles/sirs/`  
`python client.py --login davidmatos --fetch-individual myprivatefiles/apresentacao.txt`  
`python client.py --login davidmatos --fetch-individual myprivatefiles/sirs/`  
`python client.py --login davidmatos --delete-individual`  
`python client.py --login davidmatos --fetch-all-individual`  
`python client.py --login davidmatos --list-all-users`  
`python client.py --login davidmatos --list-sharedfiles`   
`python client.py --login davidmatos --share ~/Documents/shared_document.docx`  
`python client.py --login davidmatos --share ~/Documents/mypersonaldocuments/`  
`python client.py --login davidmatos --fetch-shared mysharedfiles/shared_document.docx`  
`python client.py --login davidmatos --fetch-shared mysharedfiles/mypersonaldocuments/`  
`python client.py --login davidmatos --send-shared mysharedfiles/shared_document.docx`  
`python client.py --login davidmatos --send-shared mysharedfiles/mypersonaldocuments/`  

In case you want to work on a previous version of a file, we have stored backups in the server:   
`python client.py --login davidmatos --list-backups`  
`python client.py --login davidmatos --revert-individual`  
`python client.py --login davidmatos --revert-shared`  
