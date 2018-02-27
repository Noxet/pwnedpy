#!/usr/bin/env python3
"""
pwned.py

A simple Python script to check how "safe" a password is to use, by quering
the "Have I been pwned?" API, located at https://haveibeenpwned.com/

2018
Noxet
"""

import sys
import urllib3
import certifi
import getpass
import hashlib
from typing import Tuple


def check_password(password: str) -> Tuple[int, bool, str]:
    # use the k-anonymity model
    API = 'https://api.pwnedpasswords.com/range/'

    # get the 5 first digits from the SHA1 hash of the password
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    password_hash_trunc = password_hash[:5]
    URL = API + password_hash_trunc

    # make request to API and verify certificate
    # TODO: check http responses and catch errors!
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
    resp = http.request('GET', URL)

    password_list = resp.data.decode('utf-8').split('\r\n')

    for pwd in password_list:
        suffix, hits = pwd.split(':')
        if password_hash_trunc + suffix == password_hash:
            return hits, False, "No error"

    return 0, False, "No error"


# read password from stdin
pwd = getpass.getpass('Password to check: ')

hits, err, err_msg = check_password(pwd)
if err:
    print('Something went wrong: {}'.format(err_msg))
    sys.exit(1)

if hits == 0:
    print('No match found! You might be safe, for now...')
else:
    match_str = 'Match' if hits == 1 else 'Matches'
    print('{} {} found! Change password immediately'.format(hits, match_str))
