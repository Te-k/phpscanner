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

rule basic_webshell {
    meta:
        description = "rules for basic webshells"

    strings:
        $e = "eval(gzinflate(base64_decode("

    condition:
        any of them

}
