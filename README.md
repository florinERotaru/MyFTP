# MyFTP

A server-client based application, which provides a platform for file sharing between multiple users. The application follows the TCP/IP paradigm and is implemented with **C Socket Programming**.  For application features (i.e., the main operations that are available for the user and also for the server admin) and other more technical details such as application structure, primitives used and logical principles, check the docs above. 

Each user interacts with the server only after logging into their account, which had been previously created. A user may have different permissions for file management, these permissions are handeld in a read-write/read-only man ner. The account information such as username, password and permissions are serialized into a local static data structure. Of course, the user credentials will be transmitted in a secure way using encoding.
