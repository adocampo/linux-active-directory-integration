# vim: set fileencoding=utf-8 :

version = '1.0'

import Log
import ADObj
import SMB

import os
from Crypto.Cipher import AES
import base64
from types import *
import xml.etree.cElementTree as ET
import tempfile
import re

ms_key = '4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'
ms_aes = AES.new(ms_key.decode('hex'), AES.MODE_CBC, '\x00' * 16)

gpo_var_re = re.compile('%([a-z_][0-9a-z_]*)%', re.IGNORECASE)

def sid_from_rid(sid, rid):
    sid = sid.split('-')[:-1]
    sid.append(str(rid))
    return '-'.join(sid)

class GPOFilter(object):
    def __init__(self, ldap, user, ws, variables, obj):
        self.ldap = ldap
        self.user = user
        self.ws = ws
        self.obj = obj
        self.vars = variables
        self.value = 1

    def update(self, value):
        if self.value != -1:
            self.value = value if (value == 0) or (value == 1) else -1

    def get(self, name):
        tmp = name.lower()
        if tmp in self.vars:
            return self.vars[tmp]
        return '%{0}%'.format(name)

    def set(self, name, value):
        if type(value) is ListType:
            value = value[0]
        self.vars[name.lower()] = value

    def attr_get(self, name, default = None):
        if name in self.obj.attrib:
            data = str(self.obj.attrib[name])
            if len(data) > 0:
                return gpo_var_re.sub(lambda x: self.get(x.group(1)), data)
        else:
            self.value = -1
        return default

    def attr_get_bool(self, name):
        value = self.attr_get(name)
        if (value != '0') and (value != '1'):
            self.value = -1
        return value == '1'

    def factory(self, obj):
        if obj.tag not in gpo_filters:
            filt = GPOFilter(self.ldap, self.user, self.ws, self.vars, obj)
            filt.value = -1
            return filt
        return gpo_filters[obj.tag](self.ldap, self.user, self.ws, self.vars,
                                    obj)

    def process(self, value):
        self.evaluate()
        if (self.value >= 0) and self.attr_get_bool('not'):
            self.value = 1 - self.value
        comb = self.attr_get('bool', '').lower()
        if comb == 'and':
            if (self.value < 0) or (value < 0):
                self.value = -1
            else:
                self.value &= value
        elif comb == 'or':
            if (self.value > 0) or (value > 0):
                self.value = 1
            elif (self.value < 0) or (value < 0):
                self.value = -1
            else:
                self.value = 0
        else:
            self.value = -1
        return self.value

    def evaluate(self):
        return self.value

class GPOFilterCollection(GPOFilter):
    def evaluate(self):
        for filt in self.obj:
            Log.log.write(Log.DEBUG,
                          "Filter: {0}".format(ET.tostring(filt,
                                                          encoding = 'utf-8')))
            self.update(self.factory(filt).process(self.value))
        return self.value

class GPOFilterGroup(GPOFilter):
    def evaluate(self):
        obj = self.user if self.attr_get_bool('userContext') else self.ws
        sid = self.attr_get('sid', '').upper()
        name = self.attr_get('name', '').lower()
        if self.attr_get_bool('primaryGroup'):
            if sid == sid_from_rid(self.obj.get('objectSid'),
                                   self.obj.get('primaryGroupID')):
                self.update(1)
#            elif name == self.obj.get('???'):
#                self.update(1)
            else:
                self.update(0)
        else:
            if sid in obj.get('tokenGroups'):
                self.update(1)
            elif name in obj.get('memberOf'):
                self.update(1)
            else:
                self.update(0)
        return self.value

class GPOFilterLdap(GPOFilter):
    def evaluate(self):
        binding = self.attr_get('binding', '').lower()
        search = self.attr_get('searchFilter', None)
        attr = self.attr_get('attribute', '').lower()
        var = self.attr_get('variableName', '').lower()
        if binding.startswith('ldap:'):
            data = []
            binding = binding[5:]
            if binding.startswith('//'):
                binding = binding[2:]
                data = self.ldap.search(binding, attr, search)
            elif search:
                data = self.ldap.search(None, attr, search)
            else:
                self.update(-1)
            if len(data) > 0:
                data = next(data.itervalues())
                if attr:
                    if attr in data:
                        if var:
                            self.set(var, data[attr])
                        self.update(1)
                else:
                    self.update(1)
            else:
                self.update(0)
        else:
            self.update(-1)
        return self.value

class GPOFilterOrgUnit(GPOFilter):
    def evaluate(self):
        obj = self.user if self.attr_get_bool('userContext') else self.ws
        name = self.attr_get('name', '').lower()
        if obj.dn.endswith(name):
            self.update(1)
        else:
            self.update(0)
        return self.value

re_escape = re.compile(r'[!&*:|~\/()<>=]')

class GPO(object):
    def __init__(self, ldap, user, ws, variables, name, machine = False):
        self.ldap = ldap
        self.user = user
        self.ws = ws
        self.vars = {}
        for varname in variables:
            self.vars[varname.lower()] = variables[varname]
        self.name = name
        self.kind = 'Machine' if machine else 'User'
        name = re_escape.sub(lambda m: '\\' + hex(ord(m.group(0)[0]))[2:], name)
        gpo = ADObj.ADObj(ldap, filt = ('(&(objectClass=groupPolicyContainer)'
                                        '(displayName={0}))').format(name),
                          attrs = ['gPCFileSysPath'])
        path = gpo.get('gPCFileSysPath')[0].strip('\\').split('\\', 2)[2]
        self.path = os.path.join(path, self.kind)

    def password_decrypt(self, pwd):
        pwd += '=' * ((3 - (len(pwd) % 3)) % 3)
        data = ms_aes.decrypt(base64.b64decode(pwd))
        return data[:-ord(data[-1])].decode('utf16')

    def get(self, name):
        tmp = name.lower()
        if tmp in self.vars:
            return self.vars[tmp]
        return '%{0}%'.format(name)

    def attr_get(self, data, name, default = None):
        data = data.get(name, None)
        if data is None:
            return default
        return gpo_var_re.sub(lambda x: self.get(x.group(1)), data)

    def filter_eval(self, obj):
        for filt in obj.iterfind('Filters'):
            Log.log.write(Log.DEBUG, "Checking filters")
            if GPOFilterCollection(self.ldap, self.user, self.ws, self.vars,
                                   filt).evaluate() < 1:
                return False
        return True

    def xml_load(self, path):
        with tempfile.NamedTemporaryFile() as f:
            if SMB.smb.download('SysVol', path, f.name) <= 0:
                return None
            xml = ET.ElementTree(file = f.name)
        return xml

    def xml_drive(self, data):
        data = data.find('Properties')
        if data is None:
            return {}
        path = self.attr_get(data, 'path', '')
        letter = self.attr_get(data, 'letter', [None])[0]
        if (not letter) or (not path):
            return {}

        user = self.attr_get(data, 'userName', '')
        password = ''
        if user:
            password = self.attr_get(data, 'cpassword', '')
            if password:
                password = self.password_decrypt(password)

        data = { 'letter': letter,
                 'path': path,
                 'user': user,
                 'password': password }
        Log.log.write(Log.DEBUG, "Found drive: {0}".format(data))

        return data

    def xml_printer_share(self, data):
        name = self.attr_get(data, 'name', '')
        data = data.find('Properties')
        if data is None:
            return {}
        path = self.attr_get(data, 'path', '')
        if (not name) or (not path):
            return {}
        location = self.attr_get(data, 'location', '')
        comment = self.attr_get(data, 'comment', '')

        data = { 'name': name,
                 'type': 'smb',
                 'path': path,
                 'location': location,
                 'comment': comment }
        Log.log.write(Log.DEBUG, "Found shared printer: {0}".format(data))

        return data

    def xml_printer_port(self, data):
        data = data.find('Properties')
        if data is None:
            return {}
        name = self.attr_get(data, 'localName', '')
        ip = self.attr_get(data, 'ipAddress', '')
        if (not name) or (not ip):
            return {}
        port = self.attr_get(data, 'portNumber', '9100')
        path = self.attr_get(data, 'path', '')
        location = self.attr_get(data, 'location', '')
        comment = self.attr_get(data, 'comment', '')

        data = { 'name': name,
                 'type': 'ip',
                 'ip': ip,
                 'port': port,
                 'path': path,
                 'location': location,
                 'comment': comment }
        Log.log.write(Log.DEBUG, "Found IP printer: {0}".format(data))

        return data

    def gather_drives(self):
        path = os.path.join(self.path, 'Preferences/Drives/Drives.xml')
        xml = self.xml_load(path)
        if xml == None:
            return []
        text = ET.tostring(xml.getroot(), encoding = 'utf-8')
        Log.log.write(Log.DEBUG, "Drives.xml: {0}".format(text))
        data = []
        for drive in xml.iterfind('Drive'):
            text = ET.tostring(drive, encoding = 'utf-8')
            Log.log.write(Log.DEBUG, "Evaluating drive '{0}'".format(text))
            if not self.filter_eval(drive):
                Log.log.write(Log.DEBUG, "Drive ignored")
                continue
            data.append(self.xml_drive(drive))

        return data

    def gather_printers(self):
        path = os.path.join(self.path, 'Preferences/Printers/Printers.xml')
        xml = self.xml_load(path)
        if xml == None:
            return []
        text = ET.tostring(xml.getroot(), encoding = 'utf-8')
        Log.log.write(Log.DEBUG, "Printers.xml: {0}".format(text))
        data = []
        for printer in xml.iterfind('PortPrinter'):
            text = ET.tostring(printer, encoding = 'utf-8')
            Log.log.write(Log.DEBUG, "Evaluating printer '{0}'".format(text))
            if not self.filter_eval(printer):
                continue
            data.append(self.xml_printer_port(printer))

        for printer in xml.iterfind('SharedPrinter'):
            text = ET.tostring(printer, encoding = 'utf-8')
            Log.log.write(Log.DEBUG, "Evaluating printer '{0}'".format(text))
            if not self.filter_eval(printer):
                continue
            data.append(self.xml_printer_share(printer))

        return data

gpo_filters = {
    'FilterCollection': GPOFilterCollection,
    'FilterGroup':      GPOFilterGroup,
    'FilterLdap':       GPOFilterLdap,
    'FilterOrgUnit':    GPOFilterOrgUnit
}
