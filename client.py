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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fakebook Webcrawler')
    parser.add_argument('username', type=str)
    parser.add_argument('password', type=str)
    args = parser.parse_args()
    main(args)
