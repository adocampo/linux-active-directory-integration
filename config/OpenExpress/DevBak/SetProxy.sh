#!/bin/bash

id | grep -i "(usuaris_noproxy)"
if [[ $? -ne 0 ]]; then
    # No és membre del grup, s'ha de forçar el Proxy de sistema i Firefox

    cd /home/CORPPRO/${PAM_USER}
    echo 'http_proxy="http://iprx.imi.bcn:8080"' >> .pam_environment
    echo 'https_proxy="http://iprx.imi.bcn:8080"' >> .pam_environment
    echo 'ftp_proxy="http://iprx.imi.bcn:8080"' >> .pam_environment
    echo 'no_proxy="*.bcn"' >> .pam_environment  
    echo 'HTTP_PROXY="http://iprx.imi.bcn:8080"' >> .pam_environment
    echo 'HTTPS_PROXY="http://iprx.imi.bcn:8080"' >> .pam_environment
    echo 'FTP_PROXY="http://iprx.imi.bcn:8080"' >> .pam_environment
    echo 'NO_PROXY="*.bcn"' >> .pam_environment

    cd /home/CORPPRO/${PAM_USER}/.mozilla/firefox/41ep9vfp.default
    rm prefs.bak
    rm prefs.tmp
    cp prefs.js prefs.bak
    cp prefs.js prefs.tmp
    grep -vwE "network.proxy|signon.autologin.proxy" prefs.js > prefs.tmp
    echo 'user_pref("network.proxy.autoconfig_url", "http://cfproxy.sb.imi.bcn/proxyw7webex.pac");' >> prefs.tmp
    echo 'user_pref("network.proxy.type", 2);' >> prefs.tmp
    echo 'user_pref("signon.autologin.proxy", true);' >> prefs.tmp
    awk '!x[$0]++' prefs.tmp > prefs.js  
    rm prefs.bak
    rm prefs.tmp
else
    # És membre del grup, només s'ha de treue el Proxy del Firefox

    cd /home/CORPPRO/${PAM_USER}/.mozilla/firefox/41ep9vfp.default
    rm prefs.bak
    rm prefs.tmp
    cp prefs.js prefs.bak
    cp prefs.js prefs.tmp
    grep -vwE "network.proxy|signon.autologin.proxy" prefs.js > prefs.tmp
    echo 'user_pref("network.proxy.type", 0);' >> prefs.tmp
    echo 'user_pref("signon.autologin.proxy", true);' >> prefs.tmp
    awk '!x[$0]++' prefs.tmp > prefs.js
    rm prefs.bak
    rm prefs.tmp
fi

