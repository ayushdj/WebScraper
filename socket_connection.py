import socket
import ssl


def login_to_server(username: str, password: str, port: int):
    headers = dict()

    headers["method"] = "GET"
    headers["version"] = "HTTP/1.1"
    headers["path"] = "/"
    headers["username"] = username
    headers["password"] = password
    headers["host"] = "project2.5700.network"
    headers["cookie"] = "sessionid=ar4vbw840o7vsve404mumbpwyv9vzgxu"

    headers["content_type"] = "application/x-www-form-urlencoded"

    body = f'username={username}&password={password}\n'
    body_encoded = body.encode()
    headers["content_length"] = len(body_encoded)

    message_headers = \
        f"""{headers["method"]} {headers["path"]} {headers["version"]}\r
        Host: {headers["host"]}\r
        Content-Type: {headers["content_type"]}\r
        Connection: close\r
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r
        """
    message_encoded = message_headers.encode()
    # print(message_headers)

    payload = message_encoded #+ body_encoded

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_context = ssl.SSLContext()
    actual_socket = tls_context.wrap_socket(sock, server_hostname=headers["host"])

    actual_socket.connect((headers["host"], port))
    actual_socket.sendall(payload)
    response = actual_socket.recv(4096)
    print(response)

    print(response.decode())
    actual_socket.close()
