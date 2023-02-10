#!/usr/bin/env python3
# CLI for runninng the webcrawler.

import argparse
import socket_connection

from html_parse import parse_all_href, parse_all_secret_flags
from socket_connection import HTTPSocket


def main(args):
    client = HTTPSocket(
        host='project2.5700.network',
        port=443,
        username=args.username,
        password=args.password,
    )

    # headers = {
    #     'Host': client.host,
    #     'Cookie': f'sessionid={client.session_id}; csrftoken={client.csrftoken}',
    #     'Content-Type': 'application/x-www-form-urlencoded',
    #     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    #     'Accept-Encoding': 'gzip, deflate, compress',
    #     'Referer': f'https://{client.host}/accounts/login/',
    #     'Connection': 'close'
    # }
    headers = {
        'Host': client.host,
        'Cookie': f'sessionid={client.session_id}; csrftoken={client.csrftoken}',
        # 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        # 'Accept-Encoding': 'gzip, deflate, br'
    }

    flags = []
    queue = []
    visited = {}
    queue.append("/fakebook/")
    while len(queue) > 0 and len(flags) < 5:
        size = len(queue)
        resp = client.make_get_request(path=queue.pop(0), headers=headers, connection_alive=False)
        print("THIS IS THE RESPONSE: " + resp)
        #client.sock.close()
        break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fakebook Webcrawler')
    parser.add_argument('username', type=str)
    parser.add_argument('password', type=str)
    args = parser.parse_args()
    main(args)
