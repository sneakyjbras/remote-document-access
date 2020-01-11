## Remote Document Access
82014 - João Meira  
82069 - José Brás

### Objective
The objective of this project is to allow a client to securely store and access files on a server, as well as securely share files with other clients.

### User Private Key
The user must always keep his private key with him, securely stored, so that he can access his files anytime he wants. The user has complete control of their data and its privacy.

### Implementation
Files are stored encrypted and are only decrypted locally. Digital signatures are used to verify file's authenticity. The SSL Mutual Authentication spec is implemented to mitigate man-in-the-middle attacks.

### Application Set-Up
Please refer to the server-side and client-side README files.