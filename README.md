asgard-cli
==========

Console Asgard malware checker


Installation
==========

* go get github.com/outself/asgard-cli
* go build github.com/outself/asgard-cli
* $GOPATH/bin/asgard-cli /path/to/scan


```
Generate filelist... 8 files found
10.71414ms
Check for known malware...
722.509157ms
MALWARE dev/roll/mw/shells/uploader.php
MALWARE dev/roll/mw/shells/Php_Backdoor.php
782.629696ms
Scan unknown files...
common_encrypted_malware	cae/dev/roll/mw/shells/c100.php
common_encrypted_malware	cae/dev/roll/mw/shells/c99.php
common_encrypted_malware	cae/dev/roll/mw/shells/locus.php
php_misc_shells	cae/dev/roll/mw/shells/phpjackal1.3.php
shell_names	cae/dev/roll/mw/shells/r57.php
php_misc_shells	cae/dev/roll/mw/shells/sniper.php
2.812733388s
```
