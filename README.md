# Remote Document Access  
## Context  
This project is a continuation of my Network and Computer Security (2018/2019) course project.  

## Objective  
The objective of this project is to allow a client to securely store and access files on a server, as well as securely share files with other clients.  

## Implementation
Files are stored encrypted and are only decrypted locally. Digital signatures are used to verify file's authenticity.  
SSL Mutual Authentication spec is implemented in this project, therefore mitigating man-in-the-middle attacks.  
  
## User
The user must always keep his private key with him, securely stored, so that he can access his files anytime he wants. The user has complete control of their data and its privacy.  