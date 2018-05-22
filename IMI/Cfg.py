# vim: set fileencoding=utf-8 :

from ConfigParser import SafeConfigParser

import Log

config_name = '/etc/imi.conf'

version = '1.0'

class Cfg(object):
    def __init__(self):
        self.cfg = None
        self.wsclass = None
        self.wsenv = None

    def __del__(self):
        self.close()

    def open(self, section):
        self.cfg = SafeConfigParser()
        self.cfg.read(config_name)
        self.section = section
        self.wsclass = self.get_value('workstation', 'class')
        if not self.wsclass:
            self.wsclass = 'default'
        self.wsenv = self.get_value('workstation', 'environment')
        if not self.wsenv:
            self.wsenv = 'default'

    def close(self):
        self.cfg = None
        self.section = None
        self.wsclass = None
        self.wsenv = None

    def get_value(self, section, option):
        if not self.cfg:
            return None
        if not self.cfg.has_section(section):
            return None
        if not self.cfg.has_option(section, option):
            return None
        value = self.cfg.get(section, option)
        Log.log.write(Log.DEBUG,
                      "Option '{0}' at '{1}': '{2}'".format(option, section,
                                                            value))
        return value

    def get(self, option, section = None, default = None):
        if not section:
            section = self.section
        value = self.get_value('{0}:{1}:{2}'.format(section, self.wsclass,
                                                    self.wsenv), option)
        if value == None:
            value = self.get_value('{0}:{1}'.format(section, self.wsclass),
                                                    option)
        if value == None:
            value = self.get_value(section, option)
        if value == None:
            value = default
        return value

    def get_int(self, option, section = None, default = None):
        value = self.get(option, section, default)
        try:
            value = int(value)
        except Exception as e:
            Log.log.write(Log.DEBUG,
                          "Invalid int option value: '{0}'".format(value))
            value = default
        return value

cfg = Cfg()
