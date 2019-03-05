# remote-document-access
Hello! This project is based on a project of mine for a course on Instituto Superior Técnico named SIRS (Segurança Informática em Redes e Sistemas).  
The objective of this project is to securely access files on a server.  
Files are stored encrypted and are only decrypted locally. Furthermore, digital signatures are used to verify file's authenticity.  
SSL Mutual Authentication spec is implemented in this project so that the client and the server are both automatically authenticated with
each other.  
The user must always keep his private key with him, securely stored, so that he can access his files anytime he wants.  
This simple approach intends to give the users an improved privacy and control of the data they store remotely.  
