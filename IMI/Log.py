# vim: set fileencoding=utf-8 :

import syslog
import threading
from datetime import datetime

import Cfg
import Utils

version = '1.0'

ERR, WARN, INFO, DEBUG = 0, 1, 2, 3

class Log(object):
    ERR, WARN, INFO, DEBUG = 0, 1, 2, 3

    levels = [ 'E', 'W', 'I', 'D' ]
    mapping = [ syslog.LOG_ERR, syslog.LOG_WARNING,
                syslog.LOG_INFO, syslog.LOG_DEBUG ]

    def __init__(self):
        self.module = None
        self.file = None
        self.level = None
        self.lock = threading.Lock()

    def __del__(self):
        self.close()

    def open(self, module):
        self.module = module
        name = Cfg.cfg.get('log')
        try:
            self.level = int(Cfg.cfg.get('log-level', default = '2'))
        except Exception:
            self.level = self.INFO
        if name:
            try:
                self.file = open(name, 'ab+', 0)
            except Exception as e:
                self.file = None
                Utils.exc(("Unable to open log file '{0}' "
                           "for module '{1}'").format(name, module), e)

    def close(self):
        self.module = None
        self.level = None
        if self.file:
            self.file.close()
            self.file = None
        self.lock = None

    def write(self, lvl, msg):
        if (lvl < 0) or (lvl > self.DEBUG):
            lvl = self.ERR
        if lvl > self.level:
            return
        sl_lvl = self.mapping[lvl]
        name = self.module if self.module else '<unknown>'
        header = "{0} [{1}] #{2} {3}: ".format(str(datetime.now()),
                                               self.levels[lvl],
                                               threading.current_thread().ident,
                                               name)
        prefix = ''
        text = ''
        for line in msg.strip().split('\n'):
            text += '{0}{1}{2}\n'.format(header, prefix, line)
            prefix = '---- '
        text = text.strip()
        with self.lock:
            syslog.syslog(sl_lvl, text)
            if self.file:
                self.file.write(text + '\n')

log = Log()
