# vim: set fileencoding=utf-8 :

version = '1.0'

from types import *
from struct import *

import LDAP
import Log
import DNS

def decode_lower(data):
    return data.lower()

def decode_sid(data):
    values = unpack_from('<BB', data, 0)
    if values[0] != 1:
        Log.log.write(Log.ERR, "Invalid SID revision ({0})".format(values[0]))
        return "<Invalid SID>"
    if values[1] > 15:
        Log.log.write(Log.ERR, "SID too large ({0})".format(values[1]))
        return "<Invalid SID>"
    auth = unpack_from('>HL', data, 2)
    authority = (auth[0] << 32) + auth[1]
    subauthority = list(unpack_from('<' + 'L' * values[1], data, 8))

    items = [str(values[0]), str(authority)]
    items += [str(x) for x in subauthority]
    return "S-{0}".format('-'.join(items))

special_attrs = {
    'memberof': decode_lower,
    'objectsid': decode_sid,
    'tokengroups': decode_sid
}

class ADObj(object):
    def __init__(self, ldap, base = None, filt = None, attrs = ['*'],
                 extra = []):
        self.ldap = ldap
        if base is None:
            base = ldap.base
        attrlist = attrs[:]
        if not filt:
            attrlist += extra
        res = ldap.search(base, attrlist, filt)
        if len(res) != 1:
            if len(res) == 0:
                raise Exception("Object not found ({0}, {1})".format(base,
                                                                     filt))
            raise Exception(("Multiple objects matching "
                             "filter ({0}, {1})").format(base, filt))
        self.dn = res.keys()[0]
        self.attr = res[self.dn]

        if (len(extra) > 0) and filt:
            res = ldap.search(self.dn, extra)
            self.attr.update(res[self.dn])

        for name in self.attr:
            self.decode(name)

    def decode(self, name):
        if name in special_attrs:
            data = self.attr[name]
            if type(data) is ListType:
                res = []
                for item in data:
                    res.append(special_attrs[name](item))
            else:
                res = special_attrs[name](data)
            self.attr[name] = res

    def get(self, name, default = None):
        name = name.lower()
        if name not in self.attr:
            res = self.ldap.search(self.dn, name)
            value = default
            if self.dn in res:
                value = res[self.dn][name]
            self.attr[name] = value
            self.decode(name)
        return self.attr[name]
