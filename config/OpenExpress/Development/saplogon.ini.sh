#!/bin/bash

# Script responsible of copy default SAPGUI settings to local user.
# on login time.

# If the SAPGUILandscape.xml location and files doesn't exists...
if [ ! -f /home/CORPPRO/$PAM_USER/.SAPGUI/SAPGUILandscape.xml ]
then
    #...then we create the path and the needed files to start it, with the proper owner.
    mkdir /home/CORPPRO/$PAM_USER/.SAPGUI/
    cp /etc/default/SAPGUILandscape.xml /home/CORPPRO/$PAM_USER/.SAPGUI/SAPGUILandscape.xml
    touch /home/CORPPRO/$PAM_USER/.SAPGUI/settings
    chown -R $PAM_USER:"usuarios del dominio" /home/CORPPRO/$PAM_USER/.SAPGUI
fi
