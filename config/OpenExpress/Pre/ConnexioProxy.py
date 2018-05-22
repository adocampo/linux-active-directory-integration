#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

###############################################################################
# #Instal·lació mòduls --> ConenxioProxy.sh
#    sudo apt-get install python3-setuptools
#    sudo easy_install3 pip
#    sudo apt install python-pip
#    pip install --upgrade pip
#
#    pip install pylint
#
#    pip install selenium
#
#    wget https://github.com/mozilla/geckodriver/releases/download/v0.16.1/geckodriver-v0.16.1-linux64.tar.gz
#    sudo sh -c 'tar -x geckodriver -zf geckodriver-v0.16.1-linux64.tar.gz -O > /usr/bin/geckodriver'
#    sudo chmod +x /usr/bin/geckodriver
#    rm geckodriver-v0.16.1-linux64.tar.gz
#
#    sudo apt-get install xvfb
#    pip install pyvirtualdisplay
###############################################################################

import os
import urllib
import traceback
from selenium import webdriver
from pyvirtualdisplay import Display

homepath = os.path.expanduser(os.getenv('HOME'))
profilePath = homepath + "/.mozilla/firefox/41ep9vfp.default"
driverLog = homepath + "/.mozilla/firefox/41ep9vfp.default/geckodriver.log"
url_hostname = "http://iprx.imi.bcn/hostname.php"
url_id = "http://iprx.imi.bcn/id.php"

try:
    hostname = urllib.urlopen(url_hostname)
    content_hostname = hostname.readlines()[0]
    proxy = content_hostname.replace("\n", "")

    if "corppro" in proxy:
        url = "http://" + proxy + "/ntlm/info.php"
        print "Proxy: " + proxy + " (" + url + ")"
    
        display = Display(visible=0, size=(800, 600))
        display.start()

        profile = webdriver.FirefoxProfile(profilePath)
        driver = webdriver.Firefox(profile)
        driver.implicitly_wait(30)
        driver.get(url)
        driver.close()

        display.stop()

        content_id = urllib.urlopen(url_id)
        for line in content_id.readlines():
            print line.replace("\n", "")
    else:
        print "No es pot determinar el servidor Proxy !!!"
except Exception:
    print "Error !!!"
    print traceback.format_exc()
finally:
    print "Fi"
