#! /usr/bin/python2
import yara
import argparse
import os
import fnmatch
import json
import hashlib
import time
from phpmalwarescanner import is_hacked
from collections import Counter


class PhpAnalyzer(object):
    def __init__(self):
        self.hashdb = json.load(open(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'md5ref.json'
            )
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
        try:
            md5 = self._md5_file(path)
            for fn in self.hashdb.keys():
                if fn in path:
                    known = True
                    suspicious = True
                    try:
                        return True, False, self.hashdb[fn][md5]
                    except KeyError:
                        pass
        except IOError:
            pass

        return known, suspicious, []


class PhpScanner(PhpAnalyzer):
    def __init__(
            self, signature=True, pms=True, hashes=True,
            suspicious=False, verbosity=0
            ):
        super(PhpScanner, self).__init__()
        self.yara_files = [
            "yara/phpbackdoor.yara",
            "yara/clamavphp.yara"
        ]
        self.suspicious = suspicious
        self.verbosity = verbosity
        self.signature = signature
        self.pms = pms
        self.hashes = hashes
        if suspicious:
            self.yara_files.extend(
                    ['yara/suspicious.yara', 'yara/phpsuspicious.yara']
            )
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
            try:
                res += rule.match(path)
            except yara.Error:
                pass
        return res

    def check_file(self, path):
        """Check file with means selected"""
        results = {'suspicious': False}
        if self.signature:
            sigs = self.check_file_signature(path)
            if len(sigs) > 0:
                results['suspicious'] = True
                results['signatures'] = sigs
        if self.pms:
            if fnmatch.fnmatch(path, '*.php') or fnmatch.fnmatch(path, '*.js'):
                pms = is_hacked(path)
                if pms['score'] > self.pms_score:
                    results['suspicious'] = True
                    results['pms'] = pms
        if self.hashes:
            knownhash = self.check_known_hash(path)
            if knownhash[0] and knownhash[1]:
                results['suspicious'] = True
                results['hash'] = 'BAD'

        return results

    def print_results(self, path, results):
        """Display results"""
        if results['suspicious']:
            reason = ""
            if 'signatures' in results.keys():
                reason += '[SIGNATURE (' + ", ".join(map(
                    lambda x: x.rule,
                    results['signatures']
                    )) + ')] '
            if 'pms' in results.keys():
                if self.verbosity == 0:
                    reason += "[PMS] "
                else:
                    reason += "[PMS (score: %i, %s)] " % (results['pms']['score'], ', '.join(map(lambda x: x['rule'], results['pms']['details'])))
            if 'hash' in results.keys():
                reason += "[HASH]"

            print('%s -> %s' % (path, reason))
        else:
            if self.verbosity > 3:
                print('%s : CLEAN' % path)

    def scan_file(self, path, display=True):
        """Scan files with all means possible"""
        # For each file, make all the tests
        res = self.check_file(path)
        if display:
            self.print_results(path, res)
        return res


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
    parser.add_argument(
            'FILE', nargs='+',
            help='List of files or directories to be analyzed')
    parser.add_argument(
            '-s', '--suspicious', action='store_true',
            help="Add rules for suspicious files (more FP)")
    parser.add_argument(
            '-O', '--fingerprint', action='store_true',
            help="Fingerprint the framework version")
    parser.add_argument(
            '-v', '--verbose', action="count", default=0,
            help="verbose level... repeat up to three times.")
    parser.add_argument(
            '-1', '--signature', action='store_true',
            help="Uses only the signatures")
    parser.add_argument(
            '-2', '--pms', action='store_true',
            help="Uses only the Php Malware Scanner tool")
    parser.add_argument(
            '-3', '--hash', action='store_true',
            help="Uses only the hash comparison")
    parser.add_argument(
            '-q', '--quiet', action='store_true',
            help="Hide scan summary")

    args = parser.parse_args()

    if args.fingerprint:
        fingerprinter = Fingerprinter()
    else:
        if not args.signature and not args.pms and not args.hash:
            scanner = PhpScanner(
                True,
                True,
                True,
                args.suspicious,
                args.verbose
            )
        else:
            scanner = PhpScanner(
                args.signature,
                args.pms,
                args.hash,
                args.suspicious,
                args.verbose
            )
    suspicious_files = 0
    scanned_files = 0
    start_time = time.time()

    # Browse directories
    for target in args.FILE:
        if os.path.isfile(target):
            if args.fingerprint:
                print("Impossible de fingerprint a file")
            else:
                scanner.scan_file(target)
        elif os.path.isdir(target):
            if args.fingerprint:
                fingerprinter.go(target)
            else:
                for root, dirs, files in os.walk(target):
                    for name in files:
                        res = scanner.scan_file(os.path.join(root, name))
                        if res['suspicious']:
                            suspicious_files += 1
                        scanned_files += 1

                if not args.quiet:
                    print("--------------------------------------------")
                    print("%i files scanned" % scanned_files)
                    print("%i suspicious files found" % suspicious_files)
                    print("Execution time: %s seconds" % (time.time() - start_time))
