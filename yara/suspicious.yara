rule pharmacy {
    meta:
        author = "@tenacioustek"
        description = "Search for pharmacy related words"

    strings:
        $a = "cialis"
        $b = "viagra"
        $c = "pharmacy"
        $d = "best generic"
    condition:
        2 of them
}



rule hidden {
    meta:
        author = "@tenacioustek"
        description = "Hidden frames"

    strings:
        $a = "<div style=\"position:absolute; left:-3485px; top:-3976px;\">"

    condition:
        any of them
}
