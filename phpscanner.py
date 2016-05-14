#! /usr/bin/python2
import yara
import argparse
import os

YARA_FILES = [
        "yara/phpbackdoor.yar",
]

def check_file(path, rules):
    """Check the file for php malware"""
    res = []
    for rule in rules:
        res += rule.match(path)

    if len(res) > 0:
        print('%s: %s' % (path, ", ".join(map(lambda x:x.rule, res))))
    return res

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Look for malicious php')
    parser.add_argument('FILE', nargs='+',
                            help='List of files or directories to be analyzed')
    parser.add_argument('-s', '--suspicious', action='store_true',
                help="Add rules for suspicious files (more FP)")
    args = parser.parse_args()

    # Compile rules
    if args.suspicious:
        YARA_FILES.append('yara/suspicious.yar')
        YARA_FILES.append('yara/phpsuspicious.yar')
    rules = []
    for f in YARA_FILES:
        rules.append(yara.compile(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), f)
        ))


    # Browse directories
    for target in args.FILE:
        if os.path.isfile(target):
            check_file(target, rules)
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                for name in files:
                    check_file(os.path.join(root, name), rules)

