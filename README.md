## PHP Scanner

PHP scanner is a tool for identifying php backdoors and php malicious code. It uses three different methods:
* Check signatures through yara rules (these rules were gathered from ClamAV, [php-malware-finder](https://github.com/nbs-system/php-malware-finder) or created specially for this tool)
* Check abnormal php syntax by reusing the [php-malware-scanner](https://github.com/planet-work/php-malware-scanner)
* Check for abnormal MD5 by using a database of hashes for Wordpress, Joomla and Drupal

#### Usage

```
usage: phpscanner.py [-h] [-s] [-O] [-v] [-1] [-2] [-3] [-q] FILE [FILE ...]

Look for malicious php

positional arguments:
  FILE               List of files or directories to be analyzed

optional arguments:
  -h, --help         show this help message and exit
  -s, --suspicious   Add rules for suspicious files (more FP)
  -O, --fingerprint  Fingerprint the framework version
  -v, --verbose      verbose level... repeat up to three times.
  -1, --signature    Uses only the signatures
  -2, --pms          Uses only the Php Malware Scanner tool
  -3, --hash         Uses only the hash comparison
  -q, --quiet        Hide scan summary

```

#### Example

```
phpscanner.py  .
./proxy.php -> [SIGNATURE (phpobfuscator)] [PMS]
./index.php -> [PMS] [HASH]
./misc/farbtastic/leftpanelsin.php -> [SIGNATURE (phpobfuscator)] [PMS]
./sites/default/settings.php -> [HASH]
./sites/default/files/ajax.php -> [PMS]
./sites/default/files/js/help.php -> [SIGNATURE (phpobfuscator_global)] [PMS]
./sites/default/files/js/cache.php -> [SIGNATURE (phpobfuscator_global)] [PMS]
./sites/default/files/data_export_import_extendedstayminnesota.com/info45.php -> [SIGNATURE (phpobfuscator_global)] [PMS]
./sites/default/files/xmlsitemap/general63.php -> [SIGNATURE (phpobfuscator_global)] [PMS]
./sites/default/files/xmlsitemap/model.php -> [PMS]
./sites/default/files/xmlsitemap/user99.php -> [SIGNATURE (phpobfuscator_global)] [PMS]
./sites/default/files/xmlsitemap/file.php -> [SIGNATURE (phpobfuscator_global)] [PMS]
./modules/profile/ykdizt.php -> [SIGNATURE (wso)] [PMS]
./modules/menu/xqxi.php -> [SIGNATURE (phpobfuscator)] [PMS]
./modules/forum/mn.php -> [SIGNATURE (phpobfuscator)] [PMS]
--------------------------------------------
5432 files scanned
15 suspicious files found
Execution time: 95.2635200024 seconds
```

#### Fingerprint

As the tool embedds a list of md5 hashes for Drupal, Joomla and Wordpress files, it is possible to use it to fingeprint the version of a CMS:
```
phpscanner.py  -O .
Seems to be DRUPAL7.17 (115 files)
Can also be DRUPAL7.18 (115), DRUPAL7.19 (115), DRUPAL7.21 (115), DRUPAL7.20 (115)
```

Last CMS versions included are:
* Wordpress 4.5.2
* Drupal 9.x-dev
* Joomla 3.6 alpha

#### Licence

* PHPscanner is under [MIT licence](https://github.com/Te-k/phpscanner/blob/master/LICENSE)
* [php-malware-scanner](https://github.com/planet-work/php-malware-scanner/) is under [MIT licence](https://github.com/planet-work/php-malware-scanner/blob/master/LICENSE)
* [php-malware-finder](https://github.com/nbs-system/php-malware-finder/) is under [GPLv3 licence](https://github.com/nbs-system/php-malware-finder/blob/master/php-malware-finder/LICENSE)
* The YARA project is licensed under the Apache v2.0 licence
* [ClamAV](https://www.clamav.net/) is under GPL licence
