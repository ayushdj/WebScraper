import re
import socket
import ssl
import time

CLRF: str = '\r\n'

class HTTPSocket:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.http_version = 'HTTP/1.1'
        self.username = username
        self.password = password
        self.session_id = None
        self.csrftoken = None
        self.csrfmiddlewaretoken = None
        self._get_cookies()
        self._login()

    def _get_cookies(self) -> None:
        response = self.make_get_request(
            path='/accounts/login/',
            headers={
                'Host': self.host,
            }
        )
        sessionid_regex: str = r'sessionid=(\w+)'
        sessionid_pattern = re.compile(sessionid_regex)

        csrftoken_regex: str = r'csrftoken=(\w+)'
        csrftoken_pattern = re.compile(csrftoken_regex)

        csrfmwtoken_regex: str = r'name="csrfmiddlewaretoken" value="(.+)"'
        csrfmwtoken_pattern = re.compile(csrfmwtoken_regex)

        try:
            sessionid: str = re.findall(sessionid_pattern, response)[0]
            self.session_id = sessionid

        except Exception as e:
            print('An error occurred while parsing sessionid', e)

        try:
            csrftoken: str = re.findall(csrftoken_pattern, response)[0]
            self.csrftoken = csrftoken

        except Exception as e:
            print('An error occurred while parsing csrftoken', e)

        try:
            csrfmwtoken: str = re.findall(csrfmwtoken_pattern, response)[0]
            self.csrfmiddlewaretoken = csrfmwtoken

        except Exception as e:
            print('An error occurred while parsing csrfmwtoken', e)

    def _parse_response_code(self, line: str) -> int:
        response_code_regex: str = r'HTTP/1.1 ([0-9]{3})'
        response_code_pattern = re.compile(response_code_regex)

        try:
            response_code: int = re.findall(response_code_pattern, line)[0]
            return response_code

        except Exception as e:
            print('An error occurred while parsing response code', e)

        return 0

    def _login(self):
        sock = self.create_socket_connection()
        request_headline = ' '.join(['POST', '/accounts/login/', self.http_version])

        body = f'username={self.username}&password={self.password}&csrfmiddlewaretoken={self.csrfmiddlewaretoken}&next=' + CLRF
        headers = {
            'Host': self.host,
            'Cookie': f'sessionid={self.session_id}; csrftoken={self.csrftoken}',
            'Content-Length': len(body.encode()),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, compress',
            'Referer': f'https://{self.host}/accounts/login/',
            'Connection': 'close'
        }

        payload = request_headline + CLRF + CLRF.join(f'{k}: {v}' for k, v in headers.items()) + (CLRF * 2) + body
        sock.sendall(payload.encode())
        self.socket_recv_all(sock)

    def make_get_request(self, path: str, headers: dict, connection_alive: bool=False) -> str:
        """
        Send an HTTP request over the socket.

        Args:
            path: the href to send the HTTP request to
            headers: dictionary of headers to attach to request
            connection_alive: whether or not to persist the connection to server
        Returns:
            str: response from the request as a string
        """
        sock = self.create_socket_connection()

        if connection_alive:
            headers['Connection'] = 'keep-alive'
        else:
            headers['Connection'] = 'close'

        request_headline = ' '.join(['GET', path, self.http_version])
        payload = request_headline + CLRF + CLRF.join(f'{k}: {v}' for k, v in headers.items()) + (CLRF*2)

        sock.sendall(payload.encode())
        response =  self.socket_recv_all(sock)
        response_code: int = int(self._parse_response_code(response.split('\n')[0]))

        if response_code == 500:
            wait = 1
            retry_response = self.make_get_request(path=path, headers=headers, connection_alive=connection_alive)
            while retry_response == '':
                time.sleep(2**wait)
                retry_response = self.make_get_request(path=path, headers=headers, connection_alive=connection_alive)
                if wait < 3:
                    wait += 1
        if response_code == 301:
            response = self._handle_redirect(response.split(CLRF*2)[0])
        return response if response_code not in [403, 404, 500] else ''

    def _handle_redirect(self, response_header: str) -> str:
        # Parse new location, perform new request.
        new_location_regex: str = r'project2.5700.network(/.+)'
        new_location_pattern = re.compile(new_location_regex)
        try:
            new_location: str = re.findall(new_location_pattern, response_header)[0]
            return self.make_get_request(path=new_location, connection_alive=True, headers={})
        except Exception as e:
            print('An error occurred while parsing the redirect location', e)
        return ''
        
    def create_socket_connection(self) -> ssl.SSLSocket:
        """
        Create a connection to the Fakebook server. Callers of this function MUST
        close the socket.

        Returns:
            SSLSocket
        """
        context = ssl.SSLContext()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = context.wrap_socket(sock, server_hostname=self.host)
        sock.connect(self.addr)
        sock.settimeout(20)
        return sock

    def socket_recv_all(self, sock: ssl.SSLSocket) -> str:
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
