# PyPass
PyPass is an account and password manager implemented in Python. The planned feature list is:

* safely storing account details, such as e-mail and password in an ChaCha20-Poly1305 encrypted vault
* strong password generation for new internet accounts with adjustable parameters
* user authentication via the Secure Remote Password Protocol (SRP Protocol)
* ability to secure the encrypted vault with only one, strong master password

# How it works
## Authentication
PyPass uses the [Secure Remote Password Protocol (SRP Protocol)](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol) 
to authenticate users and servers. The SRP Protocol is an augmented password-authenticated key exchange (PAKE) protocol.
All PAKE Protocols prevent eavesdroppers or man-in-the-middle attacks to learn any new information about
the password during protocol communication. This is achieved by applying a zero-knowledge password proof (ZKPP).
It offers high security against brute-force guessing the password or dictionary attacks.
An advantage of being an augmented PAKE protocol is that the server does not store any information that helps with deriving
the user's password.

Simply put, during the SRP Protocol the client (prover) wants to prove to the server (verifier) the knowledge of the
correct client password without giving away any information about the password itself. Any password-equivalent data is
only stored by the client and never sent to server. The protocol allows authentication in both directions, that is, the
server can authenticate that the client knows the password and the client can authenticate that the server knows about the
password (however, not the password itself). This provides additional security against phishing attacks.

Exact implementation details about the protocol can be found [here](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
or in this [repository](./src/authentication/). This [test](./src/authentication/test.py) allows running a quick example protocol interaction
between a server and a genuine client as well as a server and a malicious client trying to authenticate themselves as user.

## Encryption
The vault storing the account data of a client is encrypted by a symmetric encryption cipher. The symmetric encryption key used by
the cipher is derived by the password-based key derivation function [scrypt](https://tools.ietf.org/html/rfc7914). Thus, the symmetric encryption
key can only derived with the knowledge of the master password.

The account information in the vault is encrypted and decrypted by the client using the [ChaCha20 and Poly1305 Protocols](https://tools.ietf.org/html/rfc7539#section-3).
The stream cipher ChaCha20 and the authenticator Poly1305 are used in combination to provide Authenticated Encryption with Associated Data (AEAD).
Since the master password is never shared during authentication, only the client is able to decrypt their account information from the vault. Using the authentication tag
of the Poly1305 algorithm, the client can verify that the server sent the correct vault data. After decryption the client can then use the account data to login into the
associated account.

## Generation
TBD