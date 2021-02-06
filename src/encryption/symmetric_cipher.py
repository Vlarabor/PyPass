from base64 import b64encode, b64decode
from typing import Optional

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


class SymmetricCipher:
    """
    The symmetric cipher object used to encrypt and decrypt the vault.

    An instance of this class is created for every user session and is used
    to encrypt and decrypt the account information stored in the users vault.
    The username, password and salt are used to derive the symmetric encryption key
    used by the symmetric encryption cipher to encrypt and decrypt data. As the user
    password is never stored or sent to server, only the user client with the correct
    password can retrieve account information from the vault.

    Parameters
    ----------
    username : str
        The client's username.
    password : str
        The client's password in plain text.
    key_salt : str
        The salt used by the key derivation function.
    dk_len : int
        The length of the derived key in bytes.

    """

    def __init__(self, username: str, password: str, key_salt: str = None, dk_len: int = 32):
        self._username = username
        self._password = password
        self._dk_len = dk_len
        if key_salt is None:
            self._key_salt = b64encode(get_random_bytes(32)).decode("utf-8")
        else:
            self._key_salt = key_salt

        self._encryption_key = scrypt("".join([self._username, self._password]), self._key_salt, self._dk_len,
                                      N=2 ** 14, r=8,
                                      p=1)

    def decrypt(self, cipher_dict: dict) -> Optional[str]:
        """
        Decrypt the given cipher text.

        Parameters
        ----------
        cipher_dict : dict
            The dictionary containing the cipher text, header, nonce and tag.

        Returns
        -------
        str :
            The plain text or None.
        """
        try:
            jk = ['nonce', 'header', 'cipher_text', 'tag']
            jv = {k: b64decode(cipher_dict[k]) for k in jk}
            cipher = ChaCha20_Poly1305.new(key=self._encryption_key, nonce=jv['nonce'])
            cipher.update(jv['header'])
            return cipher.decrypt_and_verify(jv['cipher_text'], jv['tag']).decode("utf-8")
        except ValueError or KeyError:
            print("Invalid data for decryption!")
            return None

    def encrypt(self, plain_text: str) -> dict:
        """
        Encrypt the given plain text.

        Parameters
        ----------
        plain_text : str
            The plain text.

        Returns
        -------
        dict :
            A dict containing the cipher text, header, nonce, and tag.
        """
        plain_text = plain_text.encode("utf-8")
        header = b"header"
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=self._encryption_key, nonce=nonce)
        cipher.update(header)
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        jk = ['nonce', 'header', 'cipher_text', 'tag']
        jv = [b64encode(x).decode('utf-8') for x in (nonce, header, cipher_text, tag)]
        return dict(zip(jk, jv))

    def get_salt(self) -> str:
        """
        Returns the salt used for the symmetric key derivation.

        Returns
        -------
        str :
            The salt string.
        """
        return self._key_salt
