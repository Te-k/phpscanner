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

class PhpAnalyzer(object):
    def __init__(self):
        self.hashdb = json.load(open(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), 'md5ref.json')
        ))

    def _md5_file(self, path):
        """Generate the md5 of a file"""
        hash_md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def check_known_hash(self, path):
        """Compare the file with a known database"""
        known = False
        suspicious = False
        alllabels = []
        md5 = self._md5_file(path)
        for fn in self.hashdb.keys():
            if fn in path:
                known = True
                suspicious = True
                try:
                    return True, False, self.hashdb[fn][md5]
                except KeyError:
                    pass

        return known, suspicious, []

class PhpScanner(PhpAnalyzer):
    def __init__(self, signature=True, pms=True, hashes=True, suspicious=False, verbosity=0):
        super(PhpScanner, self).__init__()
        self.yara_files  = [
            "yara/phpbackdoor.yara",
            "yara/clamavphp.yara"
        ]
        self.suspicious = suspicious
        self.verbosity = verbosity
        if suspicious:
            self.yara_files.extend(['yara/suspicious.yara', 'yara/phpsuspicious.yara'])
            self.pms_score = 5
        else:
            self.pms_score = 10
        self.rules = []
        for f in self.yara_files:
            self.rules.append(yara.compile(
                os.path.join(os.path.dirname(os.path.realpath(__file__)), f)
            ))


    def check_file_signature(self, path):
        """Check Yara signatures provided on the file"""
        res = []
        for rule in self.rules:
            res += rule.match(path)
        return res


    def check_file(self, path):
        """Check files with all means possible"""
        #For each file, make all the tests
        sigs = self.check_file_signature(path)
        knownhash = self.check_known_hash(path)
        if fnmatch.fnmatch(path, '*.php') or fnmatch.fnmatch(path, '*.js'):
            pms = is_hacked(path)
        else:
            pms = {'score': -10}
        if len(sigs) > 0 or pms['score'] > self.pms_score or (knownhash[0] and knownhash[1]):
            reason = ""
            if len(sigs) > 0:
                reason += '[SIGNATURE (' +", ".join(map(lambda x:x.rule, sigs)) + ')] '
            if pms['score'] > self.pms_score:
                if self.verbosity == 0:
                    reason += "[PMS] "
                else:
                    reason += "[PMS (score: %i, %s)] " % (pms['score'], ', '.join(map(lambda x:x['rule'], pms['details'])))
            if knownhash[0] and knownhash[1]:
                reason += "[HASH]"

            print('%s -> %s' % (path, reason))
        else:
            if self.verbosity > 3:
                print('%s : CLEAN' % path)

class Fingerprinter(PhpAnalyzer):
    def do(self, path):
        """Fingerprint the framework of the given directory"""
        versions = []
        for root, dirs, files in os.walk(path):
            for name in files:
                if name.endswith(".php"):
                    path = os.path.join(root, name)
                    known, suspicious, v = self.check_known_hash(path)
                    if known and not suspicious:
                        versions.extend(v)
        result = Counter(versions)
        return result.most_common()[:5]

    def go(self, path):
        """Fingerprint and print result"""
        versions = self.do(path)
        print("Seems to be %s (%i files)" % (versions[0]))
        print("Can also be " + ", ".join(map(lambda x: "%s (%i)" % x, versions[1:])))


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
    parser.add_argument('-1', '--signature', action='store_true',
                help="Uses only the signatures")
    parser.add_argument('-2', '--pms', action='store_true',
                help="Uses only the Php Malware Scanner tool")
    parser.add_argument('-3', '--hash', action='store_true',
                help="Uses only the hash comparison")

    args = parser.parse_args()

    if args.fingerprint:
        fingerprinter = Fingerprinter()
    else:
        scanner = PhpScanner(
            args.signature,
            args.pms,
            args.hash,
            args.suspicious,
            args.verbose
        )


    # Browse directories
    for target in args.FILE:
        if os.path.isfile(target):
            if args.fingerprint:
                print("Impossible de fingerprint a file")
            else:
                scanner.check_file(target)
        elif os.path.isdir(target):
            if args.fingerprint:
                fingerprinter.go(target)
            else:
                for root, dirs, files in os.walk(target):
                    for name in files:
                        scanner.check_file(os.path.join(root, name))


