#!/bin/bash

file="/usr/bin/geckodriver"
if [ -f "$file" ]; then
	echo "$file trobat"
else
	echo "$file not trobat"

    # Instal·lació del mòduls necessaris per selenium
    sudo apt-get install python3-setuptools
    sudo easy_install3 pip
    sudo apt install python-pip
    pip install --upgrade pip
    pip install pylint
    pip install selenium
    wget https://github.com/mozilla/geckodriver/releases/download/v0.16.1/geckodriver-v0.16.1-linux64.tar.gz
    sudo sh -c 'tar -x geckodriver -zf geckodriver-v0.16.1-linux64.tar.gz -O > /usr/bin/geckodriver'
    sudo chmod +x /usr/bin/geckodriver
    rm geckodriver-v0.16.1-linux64.tar.gz
    sudo apt-get install xvfb
    pip install pyvirtualdisp
fi
