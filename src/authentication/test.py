from src.authentication.client_session import ClientSession
from src.authentication.server_session import ServerSession
from src.authentication.user_creation import generate_salt_and_verifier
from src.authentication.utils import GroupBitSize, get_group_params, HashFunc

if __name__ == "__main__":
    # Set size of residue class ring integer
    group_param_size = GroupBitSize.BIT_4096
    N, g = get_group_params(group_param_size)
    # Create a dummy user (this is done by the Client on user creation)
    s, v = generate_salt_and_verifier(HashFunc.SHA256, "TestUser", "SecureTestPassword123", N, g)

    # Create client session that wants to authenticate themselves
    client = ClientSession("TestUser", "SecureTestPassword123", group_param_size=group_param_size)
    # Create a malicious client session that wants to authenticate themselves as a genuine client
    m_client = ClientSession("TestUser", "JustGuessThePassword123", group_param_size=group_param_size)

    # Start authentication of the genuine client
    # Client -> Server: Username, random A from the residue class ring
    username, A = client.start_auth_process()
    m_username, m_A = m_client.start_auth_process()

    # Server session that verifies the client (s, v would normally be retrieved from a database)
    server = ServerSession(username, s, v, A, group_param_size=group_param_size)
    m_server = ServerSession(m_username, s, v, m_A, group_param_size=group_param_size)

    # Server -> Client: Random Challenge B with saved salt s
    salt, B = server.send_challenge()
    m_salt, m_B = m_server.send_challenge()

    # A genuine client is now able to solve the challenge (since they know their correct password)
    c_auth_hash = client.solve_challenge(salt, B)
    m_c_auth_hash = m_client.solve_challenge(m_salt, m_B)

    # Client -> Server: auth_hash proving they were able to solve the challenge
    s_auth_hash = server.verify_client_auth_hash(c_auth_hash)
    m_s_auth_hash = server.verify_client_auth_hash(m_c_auth_hash)

    # Server -> Client: auth_hash proving that the server can also solve the challenge
    client.verify_server_auth_hash(s_auth_hash)

    print(f"> Client authenticated genuine server: {client.is_authenticated()}")
    print(f"> Server authenticated genuine client: {server.is_authenticated()}")
    print(f"> Server authenticated malicious client: {m_server.is_authenticated()}")
