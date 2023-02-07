# CLI for runninng the webcrawler.

import argparse

from html_parse import parse_all_href, parse_all_secret_flags


def main(args):
    username = args.username
    password = args.password
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Fakebook Webcrawler')
    parser.add_argument('username', type=str, dest='username')
    parser.add_argument('password', type=str, dest='password')
    args = parser.parse_args()
    main(args)
