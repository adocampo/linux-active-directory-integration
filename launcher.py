#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

version = '1.0'

import sys
import os

from IMI.Cfg import cfg
from IMI.Log import log
from IMI.Core import Core
from IMI.Run import run

name = sys.argv[1] if len(sys.argv) > 1 else 'launcher'

core = Core(name, os.getenv('PAM_SERVICE'), update = True)
if not core.ready:
    sys.exit(0)

script = cfg.get('script', default = 'login.py')
args = cfg.get('script-args', default = '').split()

log.write(log.DEBUG, "Script: {0}".format(script))
log.write(log.DEBUG, "Args: {0}".format(args))

if run.script(script, args, True) <= 0:
    log.write(log.WARN, "Unable to execute main script")
