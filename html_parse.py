# HTML parsing utility functions.

import re
import typing


def parse_all_href(html: str) -> typing.List[str]:
    """
    Parse every href from an HTML document and return the results as a list.
    Only caring about links structured as /fakebook/0000.

    Args:
        html (str): html string

    Returns:
        list: list of href's as strings
    """
    a_tag_regex: str = r'<a href=\"(/fakebook/\d.+)\">'
    a_tag_pattern: typing.Pattern = re.compile(a_tag_regex)

    try:
        links: typing.List[str] = re.findall(a_tag_pattern, html)
        return links
    
    except Exception as e:
        print('An error occurred while parsing href in the document', e)

    return []


def parse_all_secret_flags(html: str) -> typing.List[str]:
    """
    Parse all secret flags from an HTML document.
    
    Args:
        html (str): html string

    Returns:
        list: list of secret flags - only the 64 length alphanumeric
    """
    secret_flag_regex: str = r'FLAG: ([\w]{64})'
    secret_flag_pattern: typing.Pattern = re.compile(secret_flag_regex)

    try:
        secret_flags: typing.List[str] = re.findall(secret_flag_pattern, html)
        return secret_flags
    except Exception as e:
        print('An error occurred while parsing secret flags in the document', e)

    return []

