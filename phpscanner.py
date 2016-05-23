#! /usr/bin/python2
import yara
import argparse
import os
import fnmatch
import json
import hashlib
import sys
from phpmalwarescanner import is_hacked
from collections import Counter

YARA_FILES = [
        "yara/phpbackdoor.yara",
        "yara/clamavphp.yara"
]

def fingerprint_framework(db, path):
    """Fingerprint the framework of the given directory"""
    versions = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if name.endswith(".php"):
                path = os.path.join(root, name)
                known, suspicious, v = check_known_hash(hashdb, path)
                if known and not suspicious:
                    versions.extend(v)
    result = Counter(versions)
    return result.most_common()[:5]


def md5_file(path):
    """Generate the md5 of a file"""
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def check_file_signature(path, rules):
    """Check Yara signatures provided on the file"""
    res = []
    for rule in rules:
        res += rule.match(path)
    return res

def check_known_hash(db, path):
    """Compare the file with a known database"""
    known = False
    suspicious = False
    alllabels = []
    md5 = md5_file(path)
    for fn in db.keys():
        if fn in path:
            known = True
            suspicious = True
            try:
                return True, False, db[fn][md5]
            except KeyError:
                pass

    return known, suspicious, []

def check_file(path, rules, db={}, pms_score=10, verbosity=0):
    """Check files with all means possible"""
    #For each file, make all the tests
    sigs = check_file_signature(path, rules)
    knownhash = check_known_hash(db, path)
    if fnmatch.fnmatch(path, '*.php') or fnmatch.fnmatch(path, '*.js'):
        pms = is_hacked(path)
    else:
        pms = {'score': -10}
    if len(sigs) > 0 or pms['score'] > pms_score or (knownhash[0] and knownhash[1]):
        reason = ""
        if len(sigs) > 0:
            reason += '[SIGNATURE (' +", ".join(map(lambda x:x.rule, sigs)) + ')] '
        if pms['score'] > pms_score:
            if verbosity == 0:
                reason += "[PMS] "
            else:
                reason += "[PMS (score: %i, %s)] " % (pms['score'], ', '.join(map(lambda x:x['rule'], pms['details'])))
        if knownhash[0] and knownhash[1]:
            reason += "[HASH]"

        print('%s -> %s' % (path, reason))
    else:
        if verbosity > 3:
            print('%s : CLEAN' % path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Look for malicious php')
    parser.add_argument('FILE', nargs='+',
                            help='List of files or directories to be analyzed')
    parser.add_argument('-s', '--suspicious', action='store_true',
                help="Add rules for suspicious files (more FP)")
    parser.add_argument('-O', '--fingerprint', action='store_true',
                help="Fingerprint the framework version")
    parser.add_argument('-v', '--verbose', action="count", default=0,
            help="verbose level... repeat up to three times.")

    args = parser.parse_args()

    # Compile rules &set options
    if args.suspicious:
        YARA_FILES.append('yara/suspicious.yara')
        YARA_FILES.append('yara/phpsuspicious.yara')
        pms_score = 5
    else:
        pms_score = 10
    rules = []
    for f in YARA_FILES:
        rules.append(yara.compile(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), f)
        ))

    hashdb = json.load(open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), 'md5ref.json')
    ))

    # Browse directories
    for target in args.FILE:
        if os.path.isfile(target):
            if args.fingerprint:
                print("Impossible de fingerprint a file")
            else:
                check_file(target, rules, hashdb, pms_score, args.verbose)
        elif os.path.isdir(target):
            if args.fingerprint:
                versions = fingerprint_framework(hashdb, target)
                print("Seems to be %s (%i files)" % (versions[0]))
                print("Can also be " + ", ".join(map(lambda x: "%s (%i)" % x, versions[1:])))
            else:
                for root, dirs, files in os.walk(target):
                    for name in files:
                            check_file(os.path.join(root, name), rules, hashdb, pms_score, args.verbose)


