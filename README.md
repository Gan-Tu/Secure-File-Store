# Secure-File-Store

[![Build Status](https://travis-ci.com/Michael-Tu/Secure-File-Store.svg?branch=master)](https://travis-ci.com/Michael-Tu/Secure-File-Store)

A secure and efficient file storage client for storing files on malicious remote storage server

### Core properties
  * **Confidentiality**: Any data placed in the file store should be available only to the user and people the user shares the file with. In particular, the server should not be able to learn any bits of information of any file the user stores, nor of the name of any file the user stores.
  * **Integrity**: the user should be able to detect if any of the user files have been modified while stored on the server and reject them if they have been. More formally, the user should only accept changes to a file if the change was performed by either the user or someone with whom the user have shared access to the file.

### Core Features
  * File Upload
  * File Download
  * File Sharing
  * File Access Revocation
  * Efficient Update for Large Files
  * Detection for Illegal File Tampering
  * Security Against Man in the Middle Attacks

### Design Doc

You can view my design choices, security implementation, and performance analysis [here](design-doc.pdf).

### Dependency

You will need Python 3 and [PyCrypto](https://github.com/dlitz/pycrypto).
