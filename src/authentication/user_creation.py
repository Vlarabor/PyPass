from typing import Tuple

from src.authentication.utils import convert_to_bytes, get_random_number, calculate_x, HashFunc, get_hash_func


def generate_salt_and_verifier(hash_func: HashFunc, username: str, password: str, n: int, g: int,
                               n_salt_bytes: int = 4) -> Tuple[
        bytes, bytes]:
    """
    Generates the salt and verifier for the given user.

    The generated salt and verifier are used by the server to authenticate
    future clients with the same username.

    Parameters
    ----------
    hash_func: HashFunc
        The hash function.
    username : str
        The client's username.
    password : str
        The client's password.
    n : int
        The Sophie-Germain prime number.
    g : int
        The generator.
    n_salt_bytes : int
        The size of the salt in bytes.

    Returns
    -------
    salt : bytes
        The random salt.
    v : bytes
        The verifier.
    """
    hash_func = get_hash_func(hash_func)
    salt = get_random_number(n_salt_bytes)
    v = pow(g, calculate_x(hash_func, username, password, salt), n)
    return convert_to_bytes(salt), convert_to_bytes(v)
