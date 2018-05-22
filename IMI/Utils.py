# vim: set fileencoding=utf-8 :

version = '1.0'

import traceback

import Log

def exc(text, e):
    Log.log.write(Log.ERR, "{0}\n{1}".format(text, traceback.format_exc(e)))
