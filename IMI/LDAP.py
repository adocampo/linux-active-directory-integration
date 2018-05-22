# vim: set fileencoding=utf-8 :

version = '1.0'

from types import *

import ldap
import Log
import DNS
import Utils

class LDAP(object):
    def __init__(self, domain):
        self.base = None
        self.ldap = None
        self.open(domain)

    def __del__(self):
        self.close()

    def open(self, domain):
        self.base = ','.join(['dc=' + x for x in domain.split('.')])
        servers = DNS.dns.resolve('_ldap._tcp.dc._msdcs.{0}'.format(domain),
                                  'SRV')
        for server in servers:
            url = 'ldap://' + server
            self.ldap = ldap.initialize(url)
            self.ldap.protocol_version = ldap.VERSION3
            self.ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            try:
                self.ldap.sasl_interactive_bind_s("", ldap.sasl.gssapi())
                Log.log.write(Log.DEBUG,
                              "Connected to LDAP on {0}".format(server))
                return
            except Exception as e:
                Utils.exc("Failed to connect to {0}".format(url), e)

        Log.log.write(Log.ERR,
                      ("Unable to connect to any DC "
                       "for domain {0}").format(domain))
        self.ldap = None

    def close(self):
        self.base = None
        if self.ldap:
            self.ldap.unbind_s()
            self.ldap = None

    def search(self, obj, attr, filt = None):
        if not self.ldap:
            Log.log.write(Log.ERR, "LDAP connection not established")
            return {}

        if obj is None:
            obj = self.base

        if type(obj) is ListType:
            obj = ','.join(obj)

        if type(attr) is not ListType:
            attr = [attr]

        Log.log.write(Log.DEBUG, "Getting {0} from {1} ({2})".format(attr, obj,
                                                                     filt))

        try:
            if filt is None:
                res = self.ldap.search_ext_s(obj, ldap.SCOPE_BASE,
                                             attrlist = attr)
            else:
                res = self.ldap.search_ext_s(obj, ldap.SCOPE_SUBTREE, filt,
                                             attr)
        except Exception as e:
            Utils.exc("Failed to query LDAP", e)
            return {}

        Log.log.write(Log.DEBUG, "Search result: {0}".format(res))

        data = {}
        if res is None:
            return data

        for dn, attrs in res:
            if dn is not None:
                tmp = {}
                for name in attrs:
                    tmp[name.lower()] = attrs[name]
                info = {}
                items = attr
                if ('+' in items) or ('*' in items):
                    items = attrs.keys()
                for name in items:
                    name = name.lower()
                    info[name] = tmp[name] if name in tmp else None
                data[dn.lower()] = info

        return data
