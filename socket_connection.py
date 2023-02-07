import socket
import ssl

HOST: str = 'project2.5700.network'
PORT: int = 443


def create_socket_connection() -> ssl.SSLSocket:
    """
    Create a connection to the Fakebook server. Callers of this function MUST
    close the socket.

    Returns:
        SSLSocket
    """
    context = ssl.SSLContext()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = context.wrap_socket(sock, server_hostname=HOST)
    sock.connect((HOST, PORT))
    sock.settimeout(20)
    return sock


def socket_recv_all(sock: ssl.SSLSocket) -> str:
    """
    Receive all bytes from the socket and return them decoded as string.
    Closes the socket upon completion.

    Args:
        sock: SSLSocket instance
    Returns:
        str: response from receiving all bytes from socket
    """
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if len(chunk) == 0:
                break
            chunks.append(chunk)
    except socket.timeout as e:
        print(e)

    sock.close()
    response = b''.join(chunks).decode()
    return response
    

def make_get_request():
    pass


def make_post_request():
    pass


def login_to_server(username: str, password: str, port: int):
    headers = {
        'method': 'GET',
        'version': 'HTTP/1.1',
        'path': '/',
        'username': username,
        'password': password,
        'host': 'project2.5700.network',
        'content_type': 'application/x-www-form-urlencoded',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    }

    sock = create_socket_connection()
    payload = f"{headers['method']} {headers['path']} {headers['version']}\r\nHost: {headers['host']}\r\nConnection: close\r\n\r\n"

    sock.sendall(payload.encode())
    response = socket_recv_all(sock)
    print(response)

