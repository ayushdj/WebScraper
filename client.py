#!/usr/bin/env python3
# CLI for runninng the webcrawler.

import argparse

from html_parse import parse_all_href, parse_all_secret_flags
from socket_connection import HTTPSocket


def main(args):
    client = HTTPSocket(
        host='project2.5700.network',
        port=443,
        username=args.username,
        password=args.password,
    )

    headers = {
        'Host': client.host,
        'Cookie': f'sessionid={client.session_id}; csrftoken={client.csrftoken}',
    }

    flags = []
    queue = []
    visited = set()
    queue.append('/fakebook/')
    while queue and len(flags) < 5:
        response = client.make_get_request(path=queue.pop(0), headers=headers, connection_alive=True)
        for href in parse_all_href(response):
            if href not in visited:
                queue.append(href)
            visited.add(href)
        flags.extend(parse_all_secret_flags(response))
        print(flags)
    client.sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fakebook Webcrawler')
    parser.add_argument('username', type=str)
    parser.add_argument('password', type=str)
    args = parser.parse_args()
    main(args)
