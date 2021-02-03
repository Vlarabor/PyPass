from typing import Tuple

from src.authentication.exceptions import IllegalParameterException, NoComparisonAuthHash
from src.authentication.utils import convert_to_bytes, convert_to_int, convert_to_string, get_group_params, \
    get_random_number, hash_args, GroupBitSize, HashFunc, get_hash_func


class ServerSession:
    """
    This class implements a server session of the Secure Remote Password Protocol (SRP Protocol).

    The server session has the role of the verifier in the zero knowledge proof. The server wants to
    verify that the client knows the username and password. During the proof neither the password
    or any information that helps with deriving the password is sent by the client. Both the client and the server
    generate a random number with which a public key is derived. Both parties can prove their authenticity by
    using the public key and their own secret without knowing the other's parties secret.

    Parameters
    ----------
    username : str or bytes
        The client's username.
    salt : bytes
        The random salt.
    verifier : bytes
        The verifier.
    bytes_pk_a : bytes
        The public key A from the client.
    group_param_size : GroupBitSize
        The size of the prime N in bits.
    hash_func : HashFunc
        The hash function used by the server.

    Attributes
    ----------
    hash_func
        The hash function used by the client.

    Raises
    ------
    IOError
        If the username is not specified.

    References
    ----------
    .. [1] Taylor, David, et al. "Using the Secure Remote Password (SRP) protocol for TLS authentication."
        Request for Comments 5054 (2007).

    .. [2] https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
    """

    def __init__(self, username: str or bytes, salt: bytes, verifier: bytes, bytes_pk_a: bytes,
                 group_param_size: GroupBitSize = GroupBitSize.BIT_2048, hash_func: HashFunc = HashFunc.SHA256):
        if not username:
            raise IOError("A Username must be specified.")
        self._username = convert_to_string(username) if type(username) is bytes else username
        self._n, self._g = get_group_params(group_param_size)
        self._salt = convert_to_int(salt)
        self.hash_func = get_hash_func(hash_func)
        self._verifier = convert_to_int(verifier)
        self._pk_a = convert_to_int(bytes_pk_a)

        if self._pk_a % self._n == 0:
            raise IllegalParameterException("A")

        self._b = get_random_number(32)
        self._k = hash_args(self.hash_func, self._n, self._g)
        self._pk_b = (self._k * self._verifier + pow(self._g, self._b, self._n)) % self._n
        self._u = hash_args(self.hash_func, self._pk_a, self._pk_b)
        self._server_secret = pow(self._pk_a * pow(self._verifier, self._u, self._n), self._b, self._n)
        self._client_auth_hash = hash_args(self.hash_func, self._pk_a, self._pk_b, self._server_secret)
        self._server_auth_hash = hash_args(self.hash_func, self._pk_a, self._client_auth_hash, self._server_secret)
        self._authenticated = False

    def send_challenge(self) -> Tuple[bytes, bytes]:
        """
        Sends the challenge to the client.

        Returns
        -------
        salt : bytes
            The random salt.
        pk_b : bytes
            The public key B.
        """
        return convert_to_bytes(self._salt), convert_to_bytes(self._pk_b)

    def verify_client_auth_hash(self, auth_hash: bytes) -> bytes or None:
        """
        Verifies if the given authentication hash is from a genuine client.

        If the server can authenticate the client, it sends it's own authentication
        hash to the client. If the client is not authenticated, the server will send
        no response.

        Parameters
        ----------
        auth_hash: bytes
            The authentication hash to verify.

        Returns
        -------
        bytes or None :
            The server authentication hash or None.

        Raises
        ------
        NoComparisonAuthHash
            If trying to compare an authentication hash before solving the server challenge.
        """
        if self._client_auth_hash is None:
            raise NoComparisonAuthHash()
        if self._client_auth_hash == convert_to_int(auth_hash):
            self._authenticated = True
            return convert_to_bytes(self._server_auth_hash)

    def is_authenticated(self):
        """
        Indicates, if the client and server authenticated each other.

        Returns
        -------
        bool:
            True, if authenticated, False otherwise.
        """
        return self._authenticated
