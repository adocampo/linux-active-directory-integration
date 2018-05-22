#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

###############################################################################
#  Instal·lació mòduls --> myCookies.sh
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
import traceback
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from pyvirtualdisplay import Display

homepath = os.path.expanduser(os.getenv('HOME'))
profilePath = homepath + "/.mozilla/firefox/41ep9vfp.default"
driverLog = homepath + "/.mozilla/firefox/41ep9vfp.default/geckodriver.log"
url = "http://c2rdst210a.corppro.imi.bcn:84/"

try:
    display = Display(visible=0, size=(800, 600))
    display.start()

    profile = webdriver.FirefoxProfile(profilePath)

    driver = webdriver.Firefox(profile)
    driver.implicitly_wait(30)
    driver.log_path=driverLog
    driver.get(url)
    cookies = driver.get_cookies()

    print "Guardant cookie"

    driver.close()

    display.stop()
except Exception:
    print "Error !!!"
    print traceback.format_exc()
finally:
    print "Fi"