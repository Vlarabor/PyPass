from typing import Tuple

from src.authentication.exceptions import IllegalParameterException, NoComparisonAuthHash
from src.authentication.utils import convert_to_bytes, convert_to_int, get_group_params, get_random_number, hash_args, \
    GroupBitSize, calculate_x, HashFunc, get_hash_func


class ClientSession:
    """
    This class implements a client session of the Secure Remote Password Protocol (SRP Protocol).

    The client session has the role of the prover in the zero knowledge proof. The client wants to
    prove to the server that it knows the username and password. During the proof neither the password
    or any information that helps with deriving the password is sent to server. Both the client and the server
    generate a random number with which a public key is derived. Both parties can prove their authenticity by
    using the public key and their own secret without knowing the other's parties secret.

    Parameters
    ----------
    username : str
        The client's username.
    password : str
        The client's password in plain text.
    group_param_size : GroupBitSize
        The size of the prime N in bits.
    hash_func : HashFunc
        The hash function used by the client.

    Attributes
    ----------
    hash_func : callable
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

    def __init__(self, username: str, password: str, group_param_size: GroupBitSize = GroupBitSize.BIT_2048,
                 hash_func: HashFunc = HashFunc.SHA256):
        if not username:
            raise IOError("A Username must be specified.")
        self._username = username
        self.password = password
        self._n, self._g = get_group_params(group_param_size)
        self.hash_func = get_hash_func(hash_func)
        self._a = get_random_number(32)
        self._pk_a = pow(self._g, self._a, self._n)
        self._k = hash_args(self.hash_func, self._n, self._g)
        self._client_secret = None
        self._client_auth_hash = None
        self._server_auth_hash = None
        self._authenticated = False

    def start_auth_process(self) -> Tuple[bytes, bytes]:
        """
        Starts the authentication process.

        This is the first step in the SRP Protocol. The Client selects a random value a,
        then obscures it in a value A with the help of the generator of the residue class ring.
        The client then sends his username and their public key A to the server.

        Returns
        -------
        username : bytes
            The client username in byte representation.
        A : bytes
            The public key A in byte representation.
        """
        return convert_to_bytes(self._username), convert_to_bytes(self._pk_a)

    def solve_challenge(self, bytes_salt: bytes, bytes_pk_b: bytes) -> bytes:
        """
        Solves the challenge given by the server.

        If the client knows the password, it can use the random value B and the
        salt in combination with it's own random values A, and a to compute a
        value S also computed by the server. Using a cryptographic hash function
        and the two public keys, the client can prove the correct computation of S.
        Therefore the client does not need to give away the actual value of S to server.

        Parameters
        ----------
        bytes_salt: bytes
            The stored salt of the server.
        bytes_pk_b: bytes
            The generated public key B of the server.

        Returns
        -------
        c_auth_hash : bytes
            Computed authentication hash.

        Raises
        ------
        IllegalParameterException
            If `B` or `u` are equal to zero modulo N.
        """
        salt = convert_to_int(bytes_salt)
        pk_b = convert_to_int(bytes_pk_b)

        if pk_b % self._n == 0:
            raise IllegalParameterException("B")

        u = hash_args(self.hash_func, self._pk_a, pk_b)

        if u % self._n == 0:
            raise IllegalParameterException("u")

        x = calculate_x(self.hash_func, self._username, self.password, salt)

        v = pow(self._g, x, self._n)

        self._client_secret = pow((pk_b - (self._k * v)), (self._a + (u * x)), self._n)
        self._client_auth_hash = hash_args(self.hash_func, self._pk_a, pk_b, self._client_secret)
        self._server_auth_hash = hash_args(self.hash_func, self._pk_a, self._client_auth_hash, self._client_secret)
        return convert_to_bytes(self._client_auth_hash)

    def verify_server_auth_hash(self, auth_hash: bytes):
        """
        Verifies if the given authentication hash is from a genuine server.

        If the client can authenticate the server, they know that the server accepted their
        authentication token as well as that they communicate with a genuine server.

        Parameters
        ----------
        auth_hash: bytes
            The authentication hash to verify.

        Raises
        ------
        NoComparisonAuthHash
            If trying to compare an authentication hash before solving the server challenge.
        """
        if self._server_auth_hash is None:
            raise NoComparisonAuthHash()
        self._authenticated = self._server_auth_hash == convert_to_int(auth_hash)

    def is_authenticated(self) -> bool:
        """
        Indicates, if the client and server authenticated each other.

        Returns
        -------
        bool:
            True, if authenticated, False otherwise.
        """
        return self._authenticated
