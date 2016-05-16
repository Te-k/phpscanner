rule  ajaxcommand
{
    meta:
        description = "Ajax Command shell"
        url = "https://github.com/tennc/webshell/blob/master/xakep-shells/PHP/Ajax_PHP%20Command%20Shell.php.txt"

    strings:
        $a = "Ajax Command Shell by"
        $b = "a href=http://www.ironwarez.info"
        $c = "'Clear History' => 'ClearHistory()'"
        $d = "for some ehh...help"

    condition:
        any of them
}

rule angel_shell {
    meta:
        decsription = "rule for angel shell"
        url = "https://github.com/tennc/webshell/blob/master/xakep-shells/PHP/2008.php.php.txt"

    strings:
        $a = "Codz by angel(4ngel)"
        $b = "http://www.4ngel.net"
        $c = "程序配置"
        $d = "DROP TABLE tmp_angel"
        $e = "cf('/tmp/angel_bc',$back_connect)"
        $f = "$res = execute('gcc -o /tmp/angel_bc /tmp/angel_bc.c')"
        $g = "Security Angel Team [S4T]"

    condition:
        any of them
}

rule b374k {
    meta:
        description = "b374k shell"

    strings:
        $a = "fb621f5060b9f65acf8eb4232e3024140dea2b34"
        $b = "'ev'.'al'.'(\"?>\".gz'.'in'.'fla'.'te(ba'.'se'.'64'.'_de'.'co'.'de($x)));'"
        $c = "$b374k=$func("
        $d = "$x=gzin\".\"flate(base\".\"64_de\".\"code"
        $e = "0de664ecd2be02cdd54234a0d1229b43"
        $f = "'$x,$y','ev'.'al'.'(\"\\$s_pass=\\\"$y\\\";?>\".gz'.'inf'.'late'.'( bas'.'e64'.'_de'.'co'.'de($x)));'"
        $g = "$_COOKIE['b374k']"

    condition:
        any of them
}

rule c100 {
    meta:
        description = "c100 webshell"

    strings:
        $a = "$_REQUEST[\"k1r4_surl\"]"
        $b = "MeTaLTeaM (ORG) was here"
        $c = "http://emp3ror.com/kira/"
        $d = "Owned by MeTaLTeaM"
        $e = "k1r4_buff_prepare"
        $f = "k1r4_datapipe_c.txt"
        $g = "Undetectable version by <br> Spyk1r4 <br>"
        $h = "Thanks for using MeTaLTeaM"
        $i = "FTP Quick Brute (called MeTaLTeaM . oRg"

    condition:
        any of them

}

rule c99 {
    meta:
        description = "c99 webshell"

    strings:
        $a = "$_REQUEST[\"c999sh_surl\"]"
        $b = "http://ccteam.ru/"
        $c = "c999ftpbrutecheck"
        $d = "Owned by hacker"
        $e = "c999_sess_put"
        $f = "Dumped by c999Shell.SQL v. "
        $g = "Kernel attack (Krad.c) PT2"
        $h = "http://r57shell.net"
        $i = "RootShell Security Group"

    condition:
        any of them
}

rule cyb3rsh3ll {
    meta:
        description = "cyb3rsh3ll"

    strings:
        $a = "cyb3r.gladiat0r@gmail.com"
        $b = "cyb3r sh3ll :)"
        $c = "Owned by cyb3r.gladiat0r"
        $d = "Your Shell(cyb3r-Sh3ll) located at"
        $e = "http://s15.postimage.org/94kp4a0ej"
        $f = "cyb3r 9ladiat0r"

    condition:
        any of them
}

rule r57 {
    meta:
        description = "r57 webshell"

    strings:
        $a = "<a href=http://rst.void.ru>r57shell</a>"
        $b = "'eng_text1' =>'Executed command'"
        $c = "http://127.0.0.1/r57shell/"
        $d = "$_POST['from'] = 'billy@microsoft.com'"

    condition:
        any of them
}

rule simatacker {
    meta:
        description = "simatacker"

    strings:
        $a = "SimAttacker - Vrsion :"
        $b = " - priv8 4 My friend"
        $c = "primission Not Allow change Chmod"
        $d = "Iranian Hackers : WWW.SIMORGH-EV.COM"
        $e= "admin(at)simorgh-ev(dot)com"
        $f = "Fake Mail- DOS E-mail By Victim Server"
        $g = "Welcome T0 SimAttacker 1.00  ready 2 USe"
        $h = "www.r57.biz"

    condition:
        any of them
}

rule sosyete {
    meta:
        description = "sosyete"

    strings:
        $a = "Sosyete Safe Mode Bypass Shell"
        $b = "in ortak karisimi olarak sunulmustur"

    condition:
        any of them
}

rule phpobfuscator {
    meta:
        description = "rule for different php obfuscators"

    strings:
        $a = "$O10I0I01O1OI01OIOI"
        $b = "$OI0IO10101OI0I01"
        $c = "PHP Encode v1.0 by zeura.com"
        $d = "file(__FILE__);eval(base64_decode("
        $e = "$_POST['g__g_']"
        $f = "$_uU(101).$_uU(118).$_uU(97).$_uU(108)"
        $g = "$O00O0OO___"
        $h = "$O0__O00O_O"
        $i = "_$(edoced_46esab"
        $j = "str_rot13(chr(113).\"rsva\""
        $k = "\"b\".\"\".\"as\".\"e\".\"\".\"\".\"6\".\"4\".\"_\".\"de\".\"\".\"c\".\"o\".\"\".\"d\".\"e\""

    condition:
        any of them
}

rule wso {
    meta:
        description = "WSO webshell"
        url = "https://github.com/tennc/webshell/tree/master/php/wso"
        author = "@tenacioustek"

    strings:
        $a = "63a9f0ea7bb98050796b649e85481845"
        $b = "$default_action = 'FilesMan'"
        $c = "function WSOstripslashes"
        $d = "function WSOsetcookie"
        $e = "WSO_VERSION"
        $f = "<h1>Suicide</h1><div class=content>Really want to remove the shell?"
        $g = "CREATE TABLE wso2(file text);"

    condition:
        any of them
}


rule koplak {
    meta:
        description = "koplak webshell"

    strings:
        $a = "Hacked by sky_oot"
        $b = "fuck_malaysia"

    condition:
        any of them

}

rule darkshell {
    meta:
        author = "@tenacioustek"
        description= "Darkshell"

    strings:
        $a = "<center><h1>Dark Shell</h1></center><p><hr><p>"
        $b = "$current = htmlentities ($_SERVER ['PHP_SELF'] . \"?dir=\" . $dir)"

    condition:
        any of them
}

rule webshell_functions {
    meta:
        description = "rules for basic webshell functions"
        author = "@tenacioustek"

    strings:
        $a = "find / -type f -name .htpasswd"
        $b = "find . -type f -name .bash_history"
        $c = "/usr/local/apache/conf/httpd.conf"
        $d = "/var/cpanel/accounting.log"
        $e = "http://www.packetstormsecurity.org"
        $f = "which wget curl w3m lynx"
        $g = "sysctl -n kernel.osrelease"
        $h = "ipconfig /all"
        $i = "dir /s /w /b index.php"

    condition:
        any of them
}
private rule IRC
{
    strings:
        $ = "USER" fullword
        $ = "PASS" fullword
        $ = "PRIVMSG" fullword
        $ = "MODE" fullword
        $ = "PING" fullword
        $ = "PONG" fullword
        $ = "JOIN" fullword
        $ = "PART" fullword

    condition:
        5 of them
}

rule Websites
{
    strings:
        $ = "1337day.com" nocase
        $ = "antichat.ru" nocase
        $ = "ccteam.ru" nocase
        $ = "crackfor" nocase
        $ = "darkc0de" nocase
        $ = "egyspider.eu" nocase
        $ = "exploit-db.com" nocase
        $ = "fopo.com.ar" nocase  /* Free Online Php Obfuscator */
        $ = "hashchecker.com" nocase
        $ = "hashkiller.com" nocase
        $ = "md5crack.com" nocase
        $ = "md5decrypter.com" nocase
        $ = "milw0rm.com" nocase
        $ = "milw00rm.com" nocase
        $ = "packetstormsecurity" nocase
        $ = "rapid7.com" nocase
        $ = "securityfocus" nocase
        $ = "shodan.io" nocase
        $ = "github.com/b374k/b374k" nocase
        $ = "mumaasp.com" nocase

    condition:
        any of them
}

rule php_exploit_GIF
{
meta:
	author = "@patrickrolsen"
	maltype = "GIF Exploits"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$string1 = "; // md5 Login" nocase
	$string2 = "; // md5 Password" nocase
	$string3 = "shell_exec"
	$string4 = "(base64_decode"
	$string5 = "<?php"
	$string6 = "(str_rot13"
	$string7 = {3c 3f 70 68 70} // <?php
condition:
	($magic at 0) and any of ($string*)
}

rule html_exploit_GIF
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shells"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$string1 = {3c 68 74 6d 6c 3e} // <html>
	$string2 = {3c 48 54 4d 4c 3e} // <HTML>
condition:
	($magic at 0) and (any of ($string*))
}

rule web_shell_crews
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shell Crews"
	version = "0.4"
	reference = "http://www.exploit-db.com/exploits/24905/"
	date = "12/29/2013"
strings:
	$mz = { 4d 5a } // MZ

	$string1 = "v0pCr3w"
	$string2 = "BENJOLSHELL"
	$string3 = "EgY_SpIdEr"
	$string4 = "<title>HcJ"
	$string5 = "0wn3d"
	$string6 = "OnLy FoR QbH"
	$string7 = "wSiLm"
	$string8 = "b374k r3c0d3d"
	$string9 = "x'1n73ct|d"
	$string10 = "## CREATED BY KATE ##"
	$string11 = "Ikram Ali"
	$string12 = "FeeLCoMz"
	$string13 = "s3n4t00r"
	$string14 = "FaTaLisTiCz_Fx"
	$string15 = "feelscanz.pl"
	$string16 = "##[ KONFIGURASI"
	$string17 = "Created by Kiss_Me"
	$string18 = "Casper_Cell"
	$string19 = "# [ CREWET ] #"
    	$string20 = "BY MACKER"
    	$string21 = "FraNGky"
    	$string22 = "1dt.w0lf"
    	$string23 = "Modification By iFX" nocase
condition:
	not $mz at 0 and any of ($string*)
}

rule misc_php_backdoor
{
    meta:
        author = "@patrickrolsen"
        version = "0.4"
        data = "12/29/2013"
        reference = "Virus Total Downloading PHP files and reviewing them..."
    strings:
        $mz = { 4d 5a } // MZ
        $php = "<?php"
        $string1 = "eval(gzinflate(str_rot13(base64_decode("
        $string2 = "eval(base64_decode("
        $string3 = "eval(gzinflate(base64_decode("
        $string4 = "cmd.exe /c"
        $string5 = "eva1"
        $string6 = "urldecode(stripslashes("
        $string7 = "preg_replace(\"/.*/e\",\"\\x"
        $string8 = "<?php echo \"<script>"
        $string9 = "'o'.'w'.'s'" // 'Wi'.'nd'.'o'.'w'.'s'
        $string10 = "preg_replace(\"/.*/\".'e',chr"
        $string11 = "exp1ode"
        $string12 = "cmdexec(\"killall ping;"
        $string13 = "r57shell.php"
        $string14 = "eval(\"?>\".gzuncompress(base64_decode("
        $string15 = /eval\(\$_POST\[[a-zA-Z0-9]+\]\)/
        $string16 = "tistittirti_rtietipltiatice"
        $string17 = "$qV[4].$qV[3].$qV[2].$qV[0].$qV[1]"
        $string18 = "$xsser=base64_decode($_POST"
        $string19 = "preg_replace('/(.*)/e', @$_POST["
        $string20 = "eval(\"?>\".base64_decode("
        $string21 = "$k=\"ass\".\"ert\"; $k(${\"_PO\".\"ST\"}"
        $string22 = "eval(\"return eval("
        $string23 = "preg_replace('/ad/e','@'.str_rot13("
    condition:
        not $mz at 0 and $php and any of ($string*)
}

rule pseudo_darkleech {
    meta:
        author = "@tenacioustek"
        description = "rule for pseudo darkleech malicious code"
        url = "https://blog.sucuri.net/2015/12/evolution-of-pseudo-darkleech.html"

    strings:
        $a = "function request_url_data"
        $b = "$url .= chr(ord($encrypted_url[$i]) ^ 3)"
        $c = "curl_init and fsockopen disabled"

    condition:
        any of them
}

rule jpg_web_shell
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "12/19/2013"
	reference = "http://www.securelist.com/en/blog/208214192/Malware_in_metadata"
strings:
	$magic = { ff d8 ff e? } // e0, e1, e8
	$string1 = "<script src"
	$string2 = "/.*/e"
	$string3 = "base64_decode"
condition:
	($magic at 0) and 1 of ($string*)
}

rule phpmailer {
    meta:
        description = "php mass mailer"

    strings:
        $a = "SUNT LA emailul"
        $b = "(EMAIL VERIFICARE)"
        $c = "phpmailerException"
        $d = "addAddress('tsegadora@yahoo.com'"
        $e = "class PHPMailer"
        $f = "1af98609adf796b21c9fc735e31c57b7"
        $g = "$SANDY_NR = rand($SandyNRA,$SandyNRB)"
        $h = "uplod Sucess By w4l3XzY3"
        $i = "B L E S S E D S I N N E R"
        $j = "BlesseD MAILER 2014"

    condition:
        any of them
}
