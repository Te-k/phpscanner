rule SuspiciousEncoding
{
    condition:
        base64 or hex
}

rule DodgyStrings
{
    strings:
        $ = ".bash_history"
        $ = /AddType\s+application\/x-httpd-php/ nocase
        $ = /php_value\s*auto_prepend_file/ nocase
        $ = /SecFilterEngine\s+Off/ nocase  // disable modsec
        $ = /Add(Handler|Type|OutputFilter)\s+[^\s]+\s+\.htaccess/ nocase
        $ = ".mysql_history"
        $ = ".ssh/authorized_keys"
        $ = "/(.*)/e"  // preg_replace code execution
        $ = "/../../../"
        $ = "/etc/passwd"
        $ = "/etc/proftpd.conf"
        $ = "/etc/resolv.conf"
        $ = "/etc/shadow"
        $ = "/etc/syslog.conf"
        $ = "/proc/cpuinfo" fullword
        $ = "/var/log/lastlog"
        $ = "/windows/system32/"
        $ = "LOAD DATA LOCAL INFILE" nocase
        $ = "WScript.Shell"
        $ = "WinExec"
        $ = "b374k" fullword nocase
        $ = "backdoor" fullword nocase
        $ = /(c99|r57|fx29)shell/
        $ = "cmd.exe" fullword nocase
        $ = "powershell.exe" fullword nocase
        $ = /defac(ed|er|ement|ing)/ fullword nocase
        $ = "evilc0ders" fullword nocase
        $ = "exploit" fullword nocase
        $ = "find . -type f" fullword
        $ = "hashcrack" nocase
        $ = "id_rsa" fullword
        $ = "ipconfig" fullword nocase
        $ = "kernel32.dll" fullword nocase
        $ = "kingdefacer" nocase
        $ = "Wireghoul" nocase fullword
        $ = "libpcprofile"  // CVE-2010-3856 local root
        $ = "locus7s" nocase
        $ = "ls -la" fullword
        $ = "meterpreter" fullword
        $ = "nc -l" fullword
        $ = "php://"
        $ = "ps -aux" fullword
        $ = "rootkit" fullword nocase
        $ = "slowloris" fullword nocase
        $ = "suhosin.executor.func.blacklist"
        $ = "sun-tzu" fullword nocase // Because quotes from the Art of War is mandatory for any cool webshell.
        $ = "uname -a" fullword
        $ = "warez" fullword nocase
        $ = "whoami" fullword
        $ = /(reverse|web|cmd)\s*shell/ nocase
        $ = /-perm -0[24]000/ // find setuid files
        $ = /\/bin\/(ba)?sh/ fullword
        $ = /hack(ing|er|ed)/ nocase
        $ = /xp_(execresultset|regenumkeys|cmdshell|filelist)/

        $vbs = /language\s*=\s*vbscript/ nocase
        $asp = "scripting.filesystemobject" nocase

    condition:
        IRC or 2 of them
}
