#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

log_name = '/var/log/login.log'

from types import *
from struct import *
import os
import sys
import ldap
import gssapi
import re
import subprocess
import xmltodict
import dns.resolver
import urllib
import syslog
import pwd
import tempfile
import cups
import apt
import shutil
import glob
import tempfile
import collections
from datetime import datetime

LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERR = 'D', 'I', 'W', 'E'

log_levels = {
    LOG_DEBUG: syslog.LOG_DEBUG,
    LOG_INFO: syslog.LOG_INFO,
    LOG_WARN: syslog.LOG_WARNING,
    LOG_ERR: syslog.LOG_ERR
}

def log(lvl, msg):
    sl_lvl = log_levels[lvl] if lvl in log_levels else syslog.LOG_ERR
    msg = '{0} [{1}] login: {2}'.format(str(datetime.now()), lvl, msg)
    syslog.syslog(sl_lvl, msg)
    if log_file:
        print >>log_file, msg

def run(cmd):
    log(LOG_DEBUG, "Executing command: {0}".format(cmd))

    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        out, err = p.communicate()
    except OSError as e:
        log(LOG_ERR,
            "Command execution failed ({0}: {1}): {2}".format(e.errno,
                                                              e.strerror,
                                                              cmd))
        return False
    except ValueError as e:
        log(LOG_ERR, "Invalid command: {0}".format(cmd))
        return False
    except Exception as e:
        log(LOG_ERR,
            "Unexpected error ({0}) executing: {1}".format(str(e), cmd))
        return False

    log(LOG_DEBUG, "cmd.out = {0}".format(out))
    log(LOG_DEBUG, "cmd.err = {0}".format(err))

    if p.returncode != 0:
        log(LOG_ERR,
            "Command returned error {0}: {1} ({2} {3})".format(p.returncode,
                                                               cmd, out, err))
        return False

    return out

def download(servers, share, src, dst):
    log(LOG_DEBUG, "Downloading //*/{0}/{1}".format(share, src))

    action = ''
    name = src
    if '/' in name:
        path, name = name.rsplit('/', 1)
        action = 'cd {0}; '.format(path)
    action += 'get {0} {1}'.format(name, dst)
    for server in servers:
        log(LOG_DEBUG, "Trying server {0}".format(server))
        unc = '//{0}/{1}'.format(server, share)
        if run(['smbclient', unc, '-E', '-k', '-c', action]) != False:
            log(LOG_DEBUG, "Got {0} from {1}".format(src, unc))
            return True

        log(LOG_WARN,
            "Failed to retrieve {0} from {1}".format(src, unc))

    return False

def step(num, text):
    log(LOG_DEBUG, "Step ({0}): {1}".format(num, text))
    try:
        with open('/tmp/login_{0}'.format(os.getenv('PAM_USER')), 'a') as f:
            f.write('{0}\n# {1}\n'.format(num, text))
    except Exception as e:
        log(LOG_WARN, "Step notify failed: {0}".format(str(e)))

def get_user():
    try:
        cred = gssapi.Credentials(usage='initiate')
    except gssapi.raw.misc.GSSError as e:
        log(LOG_ERR, "Unable to get user credentials ({0})".format(str(e)))
        return None, None

    if cred.name is None:
        log(LOG_WARN, "No GSS user credentials found");
        return None, None

    id = str(cred.name)
    if '@' not in id:
        log(LOG_ERR, "Invalid user credentials ({0})".format(id))
        return None, None

    user, realm = id.split('@', 1)
    domain = realm.lower()

    log(LOG_DEBUG, "Domain = {0}, User = {1}".format(domain, user))

    return user, domain

def ad_search(lh, obj, attr, filt = None):
    if type(obj) is ListType:
        obj = ','.join(obj)

    if type(attr) is not ListType:
        attr = [attr]

    log(LOG_DEBUG, "Getting {0} from {1} ({2})".format(attr, obj, filt))

    try:
        if filt is None:
            res = lh.search_ext_s(obj, ldap.SCOPE_BASE, attrlist = attr)
        else:
            res = lh.search_ext_s(obj, ldap.SCOPE_SUBTREE, filt, attr)
    except ldap.LDAPError as e:
        err = str(e)
        if (type(e.message) is dict) and ('desc' in e.message):
            err = e.message['desc']
        log(LOG_ERR, "Failed to query ldap: {0}".format(err))
        return {}

    log(LOG_DEBUG, "Search result: {0}".format(res))

    data = {}
    if res is None:
        return data

    for dn, attrs in res:
        if dn is not None:
            info = {}
            for name in attr:
                info[name] = attrs[name] if name in attrs else None
            data[dn] = info

    return data

def umount(mp):
    log(LOG_DEBUG, "Umount {0}".format(mp))
    return run(['umount', mp]) != False

def create_dir(path):
    log(LOG_DEBUG, "Creating directory {0}".format(path))
    if os.path.ismount(path):
        log(LOG_DEBUG, "Directory {0} is a mount point".format(path))
        return umount(path)
    if os.path.isdir(path):
        log(LOG_DEBUG, "Directory {0} already created".format(path))
        return True
    if os.path.exists(path):
        log(LOG_ERR,
            "Entry {0} already exists and it's not a directory".format(path))
        return False
    try:
        os.mkdir(path)
    except Exception as e:
        log(LOG_ERR,
            "Unable to create directory {0}: {1}".format(path, str(e)))
        return False
    log(LOG_INFO, "Directory {0} created".format(path))
    return True

def create_link(path, link):
    dirname, filename = link.rsplit('/', 1)
    log(LOG_DEBUG, "Creating link {0} to {1}".format(link, path))
    if os.path.islink(link):
        try:
            src = os.path.join(dirname, path)
            dst = os.path.join(dirname, os.readlink(link))
        except Exception as e:
            log(LOG_ERR,
                "Failed to read symbolic link {0}: {1}".format(link, str(e)))
            return False
        if src == dst:
            log(LOG_DEBUG, "Link {0} already exists".format(link))
            return True
        log(LOG_WARN, "Link {0} points to {1}".format(link, dst))
        try:
            os.remove(link)
        except Exception as e:
            log(LOG_ERR, "Unable to remove link {0}: {1}".format(link, str(e)))
            return False
        log(LOG_DEBUG, "Link {0} removed".format(link))
    if os.path.exists(link):
        log(LOG_WARN, "Entry {0} exists but it's not a link".format(link))
        now = datetime.now()
        tgt = ('{0}_{1:04d}{2:02d}{3:02d}_'
               '{4:02d}{5:02d}{6:02d}{7:06d}').format(filename, now.year,
                                                      now.month, now.day,
                                                      now.hour, now.minute,
                                                      now.second,
                                                      now.microsecond)
        try:
            os.rename(link, os.path.join(dirname, tgt))
        except Exception as e:
            log(LOG_ERR,
                "Unable to rename directory {0} to {1}: {2}".format(link, tgt,
                                                                    str(e)))
            return False
    try:
        os.symlink(path, link)
    except Exception as e:
        log(LOG_ERR, "Unable to create link {0}: {1}".format(link, str(e)))
        return False
    log(LOG_INFO, "Link {0} created".format(link))
    return True

def mount_prepare(kind, user, name):
    log(LOG_DEBUG, "Preparing mount '{0}'".format(name))
    path = '/run/user/{0}/{1}'.format(user['uid'], user['domain'])
    if not create_dir(path):
        return False
    path += '/{0}'.format(kind)
    if not create_dir(path):
        return False
    path += '/{0}'.format(name)
    if not create_dir(path):
        return False
    tgt = '{0}/{1}'.format(user['home'], name)
    return create_link(path, tgt)

def mount(user, share, name):
    if share is None:
        return
    log(LOG_DEBUG, "Mount({0}): {1} -> {2}/{3}".format(user['uid'], share,
                                                       user['home'], name))
    path = '{0}/{1}'.format(user['home'], name)
    if mount_prepare('drive', user, name):
        cmd = ['mount', '-t', 'cifs', '-o',
               'sec=krb5,cruid={0},uid={0},gid={1}'.format(user['uid'],
                                                           user['gid']),
               share.replace('\\', '/'), path]
        run(cmd)

def bind(user, path, name):
    log(LOG_DEBUG, "Bind {0} -> {1}".format(path, name))
    src = '/run/user/{0}/{1}/drive/{2}'.format(user['uid'], user['domain'],
                                               path)
    dst = '{0}/{1}'.format(user['home'], name)
    if mount_prepare('bind', user, name):
        cmd = ['mount', '-o', 'bind', src, dst ]
        run(cmd)

def parse_fmt(fmt, data, offset):
    values = unpack_from(fmt, data, offset)
    return values, data[calcsize(fmt):]

class NTSID(object):
    def __init__(self):
        self.revision = 0
        self.authority = 0
        self.subauthority = []

    def __str__(self):
        if self.revision == 0:
            return "<NULLSID>"
        items = [str(self.authority)] + [str(x) for x in self.subauthority]
        return "S-{0}-{1}".format(self.revision, '-'.join(items))

    def __len__(self):
        return 8 + len(self.subauthority) * 4

    def from_binary(self, data, pos):
        values = unpack_from('<BB', data, pos)
        if values[0] != 1:
            raise Exception("Invalid SID revision ({0})".format(values[0]))
        if values[1] > 15:
            raise Exception("SID too large ({0})".format(values[1]))
        self.revision = values[0]
        auth = unpack_from('>HL', data, pos + 2)
        self.authority = (auth[0] << 32) + auth[1]
        self.subauthority = list(unpack_from('<' + 'L' * values[1], data,
                                             pos + 8))
        return data[pos + 8 + values[1] * 4:]

    def equal(self, sid):
        if type(sid) is not ListType:
            sid = [sid]
        return str(self) in [x.upper() for x in sid]

class NTGUID(object):
    def __init__(self):
        self.data1 = 0
        self.data2 = 0
        self.data3 = 0
        self.data4 = [ 0, 0, 0, 0, 0, 0, 0, 0 ]
        fmt_data1 = '{0:08x}'
        fmt_data2 = '{1:04x}'
        fmt_data3 = '{2:04x}'
        fmt_data4 = '{3:02x}{4:02x}'
        fmt_data5 = '{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}'
        self.fmt = '{0}-{1}-{2}-{3}-{4}'.format(fmt_data1, fmt_data2,
                                                fmt_data3, fmt_data4,
                                                fmt_data5)

    def __str__(self):
        return self.fmt.format(self.data1, self.data2, self.data3,
                               self.data4[0], self.data4[1], self.data4[2],
                               self.data4[3], self.data4[4], self.data4[5],
                               self.data4[6], self.data4[7])

    def __len__(self):
        return 16

    def from_binary(self, data, pos):
        values = unpack_from('<LHHBBBBBBBB', data, pos)
        self.data1 = values[0]
        self.data2 = values[1]
        self.data3 = values[2]
        self.data4 = values[3:]

    def equal(self, guid):
        if guid is None:
            guid = '00000000-0000-0000-0000-000000000000'
        return guid.lower() == str(self)

class NTACE(object):
    def __init__(self):
        self.type = -1
        self.length = 0

    def __str__(self):
        if self.type == 0:
            return "ALLOW({0:08x},{1})".format(self.mask, str(self.sid))
        if self.type == 5:
            return "ALLOWOBJ({0:08x},{1},{2},{3})".format(self.mask,
                                                          str(self.objtype),
                                                          str(self.inhobj),
                                                          str(self.sid))
        return "UNKNOWNACE"

    def __len__(self):
        return self.length;

    def from_binary(self, data, pos):
        values = unpack_from("<BBH", data, pos)
        if (values[2] % 4) != 0:
            raise Exception("Invalid ACE size ({0})".format(values[2]))
        length = 4
        self.type = values[0]
        if self.type == 0:
            self.mask, = unpack_from("<L", data, pos + length)
            length += 4
            self.sid = NTSID()
            self.sid.from_binary(data, pos + length)
            length += len(self.sid)
        elif values[0] == 5:
            self.mask, self.flags = unpack_from("<LL", data, pos + length)
            length += 8
            self.objtype = NTGUID()
            self.inhobj = NTGUID()
            if (self.flags & 1) != 0:
                self.objtype.from_binary(data, pos + length)
                length += len(self.objtype)
            if (self.flags & 2) != 0:
                self.inhobj.from_binary(data, pos + length)
                length += len(self.inhobj)
            self.sid = NTSID()
            self.sid.from_binary(data, pos + length)
            length += len(self.sid)

        length = (length + 3) & ~3
        if length > values[2]:
            raise Exception("Broken ACE")
        self.length = values[2]

    def check(self, mask, sid, obj = None):
        if self.type == 0:
            if self.sid.equal(sid):
                return 1 if (self.mask & mask) == mask else 0
            return -1
        if self.type == 5:
            if self.sid.equal(sid) and self.objtype.equal(obj):
                return 1 if (self.mask & mask) == mask else 0
            return -1
        return 0

class NTACL(object):
    def __init__(self):
        self.revision = 0
        self.aces = []
        self.length = 0

    def __str__(self):
        if self.revision == 0:
            return "<NULLACL>"
        return "ACL({0})".format(','.join([str(ace) for ace in self.aces]))

    def __len__(self):
        self.length

    def from_binary(self, data, pos):
        values = unpack_from('<BBHHH', data, pos)
        if (values[0] != 2) and (values[0] != 4):
            raise Exception("Invalid ACL revision ({0})".format(values[0]))
        if (values[1] != 0) or (values[4] != 0):
            raise Exception("Invalid ACL structure")
        self.revision = values[0]
        length = 8
        self.aces = []
        count = values[3]
        while count > 0:
            ace = NTACE()
            ace.from_binary(data, pos + length)
            length += len(ace)
            self.aces.append(ace)
            count -= 1

        length = (length + 3) & ~3
        if length > values[2]:
            print length, values
            raise Exception("Broken ACL")
        self.length = values[2]

    def check(self, mask, sid, obj = None):
        for ace in self.aces:
            res = ace.check(mask, sid, obj)
            if res >= 0:
                return res > 0
        return False

class NTSD(object):
    def __init__(self):
        self.owner = NTSID()
        self.group = NTSID()
        self.sacl = NTACL()
        self.dacl = NTACL()

    def __str__(self):
        return "SD(O={0},G={1},S={2},D={3})".format(str(self.owner),
                                                    str(self.group),
                                                    str(self.sacl),
                                                    str(self.dacl))

    def from_binary(self, data):
        values = unpack_from('<BBHLLLL', data)
        if values[0] != 1:
            raise Exception("Invalid NTSD revision ({0})".format(values[0]))
        if (values[2] & 0x8000) == 0:
            raise Exception('Unsupported NTSD')
        self.owner = NTSID()
        self.owner.from_binary(data, values[3])
        self.group = NTSID()
        self.group.from_binary(data, values[4])
        self.sacl = NTACL()
        self.dacl = NTACL()
        if (values[2] & 0x0010) != 0:
            self.sacl.from_binary(data, values[5])
        if (values[2] & 0x0004) != 0:
            self.dacl.from_binary(data, values[6])

    def check(self, mask, sid, obj = None):
        return self.dacl.check(mask, sid, obj)

class DNSPool(object):
    def __init__(self, domain = None):
        self.servers = []
        if domain is not None:
            res = dns.resolver.query('_ldap._tcp.dc._msdcs.{0}'.format(domain),
                                     'SRV')
            self.servers = [x.target.to_text(True) for x in res]

        re_driver = r'^\s*Driver\s*Name\s*:\s*\[\s*(.+[^\s])\s*\]\s*$'
        re_share = r'^\s*sharename\s*:\s*\[\s*(.*[^\s])\s*\]\s*$'
        re_sids = r'^\s*(.+[^\s])\s+(S-1-[0-9-]+).*$'

        self.re_driver = re.compile(re_driver, re.IGNORECASE | re.MULTILINE)
        self.re_share = re.compile(re_share, re.IGNORECASE | re.MULTILINE)
        self.re_sids = re.compile(re_sids, re.IGNORECASE | re.MULTILINE)

    def rpcclient(self, cmd, host = None, pattern = None):
        if host is None:
            host = self.servers
        elif type(host) is not ListType:
            host = [host]
        for server in host:
            try:
                out = run(['rpcclient', '-k', '-c', cmd, server])
                if out == False:
                    raise Exception("Unable to execute rpcclient")
                if pattern is None:
                    return out
                match = pattern.search(out)
                if match is None:
                    log(LOG_ERR, ("rpcclient didn't return expected data as "
                                  "answer to '{0}'").format(cmd))
                    raise Exception('Requested information not found')
                return match.group(1)
            except Exception as e:
                log(LOG_WARN, "rpcclient failed on server {0}".format(server))

        raise Exception("rpcclient is unable to get requested information "
                        "from any server")

    def printer_get_driver(self, host, printer):
        driver = self.rpcclient("getdriver '{0}' 1".format(printer), host,
                                self.re_driver)
        log(LOG_DEBUG, "Driver '{0}' for printer '{1}/{2}'".format(driver,
                                                                   host,
                                                                   printer))
        return driver

    def printer_get_share(self, host, printer):
        return self.rpcclient("getprinter '{0}' 2".format(printer), host,
                              self.re_share)

    def smb_get(self, share, src, dst):
        return download(self.servers, share, src, dst)

class DriverMap(object):
    def __init__(self):
        self.maps = []
        re_map = re.compile(r'^(.+)=([^=]+)$')
        path = '{0}/drivers.map'.format(base_dir)
        with tempfile.NamedTemporaryFile() as f:
            if download(pool.servers, 'SysVol', path, f.name):
                for line in f:
                    m = re_map.match(line)
                    if m:
                        re_drv = re.compile(m.group(1).strip(), re.IGNORECASE)
                        self.maps.append([re_drv, m.group(2).strip()])

    def find(self, name):
        for drv in self.maps:
            if drv[0].search(name):
                return drv[1]
        return None

def safe_get(data, field, default = None):
    return data[field] if field in data else default

def printers_shared(data):
    data = safe_get(data, 'SharedPrinter', {})
    name = safe_get(data, '@name', '')
    data = safe_get(data, 'Properties', {})
    path = safe_get(data, '@path', '')
    if (not name) or (not path):
        return {}
    location = safe_get(data, '@location', '')
    comment = safe_get(data, '@comment', '')
    host, printer = path.strip('\\').split('\\', 1)
    share = pool.printer_get_share(host, printer)
    driver = pool.printer_get_driver(host, printer)
    driver = driver_map.find(driver)
    if not driver:
        return {}

    return { name:
            { 'url': 'smb://{0}/{1}'.format(host, share),
              'driver': driver,
              'location': location,
              'comment': comment } }

def printers_port(data):
    data = safe_get(data, 'PortPrinter', {})
    data = safe_get(data, 'Properties', {})
    name = safe_get(data, '@localName', '')
    ip = safe_get(data, '@ipAddress', '')
    if (not name) or (not ip):
        log(LOG_DEBUG, "Insufficient information for an IP printer")
        return {}
    port = safe_get(data, '@portNumber', '9100')
    path = safe_get(data, '@path', '')
    location = safe_get(data, '@location', '')
    comment = safe_get(data, '@comment', '')

    windrv = ''
    if path:
        host, printer = path.strip('\\').split('\\', 1)
        windrv = pool.printer_get_driver(host, printer)
    else:
        log(LOG_WARN, "No path defined for printer {0}".format(path))

    driver = driver_map.find(windrv)
    if not driver:
        log(LOG_WARN,
            "No driver mapping found for printer {0} ({1})".format(path,
                                                                   windrv))
        return {}

    return { name:
            { 'url': 'socket://{0}:{1}'.format(ip, port),
              'driver': driver,
              'location': location,
              'comment': comment } }

class CupsPrinters(object):
    def __init__(self, user):
        self.cups = cups.Connection()
        self.attr = 'requesting-user-name-allowed'
        self.user = user.lower()
        self.refresh()

    def refresh(self):
        self.printers = normalize_strings(self.cups.getPrinters())
        log(LOG_DEBUG, "Existing printers: {0}".format(self.printers))

    def delete(self, amount):
        log(LOG_DEBUG, "Removing printers for user {0}".format(self.user))
        count = len(self.printers)
        item = 0
        for printer in self.printers:
            step(int(amount * item / count),
                 "Eliminant impressora '{0}'".format(printer))
            item += 1
            users = self.cups.getPrinterAttributes(printer,
                                            requested_attributes = [self.attr])
            users = [x.lower() for x in users[self.attr]]
            log(LOG_DEBUG, "Removing printer {0} (users = {1})".format(printer,
                                                                       users))
            if self.user in users:
                log(LOG_DEBUG, "Removing printer {0}".format(printer))
                users.remove(self.user)
                if len(users) > 0:
                    log(LOG_DEBUG,
                        "Modifying printer {0} (users = {1})".format(printer,
                                                                     users))
                    self.cups.setPrinterUsersAllowed(printer, users)
                else:
                    log(LOG_DEBUG,
                        "Deleting printer {0}".format(printer))
                    self.cups.deletePrinter(printer)
            else:
                log(LOG_DEBUG, "Ignoring printer {0}".format(printer))
        self.refresh()
        step(amount, "Impressores eliminades")

    def install(self, name, data):
        name = name.replace(' ', '_')
        name = name.replace('/', '_')
        log(LOG_DEBUG, "Installing printer {0}".format(name))
        users = []
        if name in self.printers:
            users = self.cups.getPrinterAttributes(name,
                                            requested_attributes = [self.attr])
            users = [x.lower() for x in users[self.attr]]
            log(LOG_DEBUG,
                "Printer {0} already exists (users = {1})".format(name, users))
            if self.user in users:
                log(LOG_DEBUG, "Printer {0} already prepared".format(name))
                return
        else:
            log(LOG_DEBUG, "Creating printer {0}".format(name))
            self.cups.addPrinter(name, ppdname = data['driver'],
                                 info = data['comment'],
                                 location = data['location'],
                                 device = data['url'])
            self.cups.setPrinterShared(name, False)
            self.cups.setPrinterErrorPolicy(name, 'retry-current-job')
            self.cups.setPrinterOpPolicy(name, 'authenticated')
            self.cups.enablePrinter(name)
            self.cups.acceptJobs(name)

        users.append(self.user)
        log(LOG_DEBUG, "Modifying printer {0} (users = {1})".format(name,
                                                                    users))
        self.cups.setPrinterUsersAllowed(name, users)

def run_script(name):
    with tempfile.NamedTemporaryFile() as f:
        if download(pool.servers, 'SysVol',
                    '{0}/scripts/{1}'.format(base_dir, name), f.name):
            os.chmod(f.name, 0700)
            run([f.name])

def normalize_strings(data):
    if type(data) is UnicodeType:
        return data.encode('utf-8')
    if type(data) is ListType:
        return [normalize_strings(x) for x in data]
    if type(data) is DictType:
        res = {}
        for k in data:
            res[normalize_strings(k)] = normalize_strings(data[k])
        return res
    if type(data) is collections.OrderedDict:
        res = collections.OrderedDict()
        for k in data:
            res[normalize_strings(k)] = normalize_strings(data[k])
        return res
    if type(data) is TupleType:
        return tuple([normalize_strings(x) for x in data])
    return data

def save_icons(path, target = None):
    path = os.path.realpath(path)
    log(LOG_DEBUG, "Saving icons from {0}".format(path))
    for root, subdirs, files in os.walk(path):
        log(LOG_DEBUG, "Scanning {0}: {1}".format(root, files))
        for item in files:
            if item[-8:] != '.desktop':
                continue
            name = os.path.join(root, item)
            with open(name, 'r') as f:
                if re_disp.search(f.read()):
                    log(LOG_DEBUG, "Skipped hidden icon {0}".format(name))
                    continue
            if target:
                log(LOG_DEBUG, "Moving icon {0}".format(name))
                shutil.move(name, os.path.join(target, os.path.basename(name)))
            else:
                log(LOG_DEBUG, "Deleting icon {0}".format(name))
                os.remove(name)

log_file = None
if log_name:
    try:
        log_file = open(log_name, "w+")
    except:
        pass

log(LOG_DEBUG, str(os.environ))

# Check if we are initiating a new full session.
service = os.getenv('PAM_SERVICE')
if service not in ['sshd', 'lightdm', 'xrdp-sesman', 'sddm']:
    sys.exit(0)

run(['klist'])

# Try to get the current kerberos user. If not found (i.e. this is a local
# user) we don't do anything else.
username, domain = get_user()
if username is None:
    sys.exit(0)

user_pwd = pwd.getpwnam(username)
uid = user_pwd.pw_uid
gid = user_pwd.pw_gid
home = user_pwd.pw_dir

user = {
    'name': username,
    'home': user_pwd.pw_dir,
    'uid': user_pwd.pw_uid,
    'gid': user_pwd.pw_gid,
    'domain': domain
}

if len(sys.argv) < 1:
    log(LOG_ERR, "Missing base directory")
    sys.exit(1)

base_dir = '{0}/scripts/{1}'.format(domain, sys.argv[1])

prn = CupsPrinters(username)
step(0, "Netejant impressores")

if (os.getenv('PAM_TYPE') == 'close_session'):
    prn.delete(33)
    mounts = glob.iglob('/var/run/user/{0}/{1}/bind/*'.format(uid, domain))
    count = len(mounts)
    item = 0
    for mp in mounts:
        step(33 + int(33 * item / count), "Eliminant accessos directes")
        item += 1
        umount(mp)
    mounts = glob.iglob('/var/run/user/{0}/{1}/drives/*'.format(uid, domain))
    count = len(mounts)
    item = 0
    for mp in mounts:
        step(66 + int(33 * item / count), "Eliminant punts de muntatge")
        item += 1
        umount(mp)
    step(100, "Finalitzat")
    sys.exit(0)

log(LOG_DEBUG, "start")

prn.delete(5)

pool = DNSPool(domain)
driver_map = DriverMap()

# Connect to the LDAP using the kerberos credentials.
lh = ldap.initialize('ldap://' + domain)
lh.protocol_version = ldap.VERSION3
lh.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
lh.sasl_interactive_bind_s("", ldap.sasl.gssapi())

# Lookup the current user. This gives us the DN of the user. It will be used
# to determine the appropriate group policies associated and request specific
# attributes.
root = ['DC=' + x for x in domain.split('.')]
user_data = ad_search(lh, root, 'dn', 'sAMAccountName={0}'.format(username))
if len(user_data) != 1:
    lh.unbind_s()
    log(LOG_ERR, "Username not found in LDAP")
    sys.exit(0)

dn = user_data.keys()[0]

# Some user attributes cannot be retrieved by the initial search because they
# are specially constructed, like 'tokenGroups'. So a second search is made
# directly on the use object.
attrs = ad_search(lh, dn, ['homeDirectory', 'homeDrive', 'profilePath',
                           'extensionAttribute4', 'memberOf'])
attrs = attrs[dn]
drive = attrs['homeDrive'][0]
log(LOG_DEBUG, str(attrs['memberOf']))

step(5, "Connectant {0}".format(drive))
mount(user, attrs['homeDirectory'][0], drive)
step(6, "Connectant Z:")
mount(user, attrs['extensionAttribute4'][0], 'Z:')
step(7, "Connectant K:")
mount(user, r'\\NAS_CORP\CORP\APPS', 'K:')
step(8, "Connectant L:")
mount(user, r'\\NAS_CORP\CORP\APPS9', 'L:')

step(9, "Connectant Documents")
bind(user, '{0}/Dades'.format(drive), 'Documents')
step(10, "Connectant Vídeos")
bind(user, '{0}/My Videos'.format(drive), 'Vídeos')
step(11, "Connectant Imatges")
bind(user, '{0}/My Pictures'.format(drive), 'Imatges')
step(12, "Connectant Música")
bind(user, '{0}/My Music'.format(drive), 'Música')

# Compute the list of SIDs related to the user.
#sid = NTSID()
#sid.from_binary(bytearray(attrs['objectSid'][0]), 0)
#sids = [str(sid)]
#for group in attrs['tokenGroups']:
#    sid.from_binary(bytearray(group), 0)
#    sids.append(str(sid))

#re_ldap = re.compile(r'\[LDAP://([^;]+)[^]]*\]')

# Lookup Group Policies associated to the user.
containers = dn.split(',')
containers.pop(0)
gpos = set()
#while len(containers) > 0:
#    data = ad_search(lh, containers, 'gPLink')
#    gpos |= set([x.group(1) for x in re_ldap.finditer(data['gPLink'])])
#    containers.pop(0)

re_escape = re.compile(r'[!&*:|~\/()<>=]')

count = len(attrs['memberOf'])
item = 0
for group in attrs['memberOf']:
    step(13 + int(10 * item / count),
         "Processant grup '{0}'".format(group.split(',')[0][3:]))
    item += 1
    name = ''
    if group[:19].upper() == 'CN=GPO_UNIFLOW_COL,':
        name = 'PRINT_Uniflow_IMI_COLOR'
    elif group[:18].upper() == 'CN=GPO_UNIFLOW_BN,':
        name = 'PRINT_Uniflow_IMI_BN '
    elif group[:5].upper() == 'CN=PR':
        name = group.split(',')[0][3:]
    if name:
        name = re_escape.sub(lambda m: '\\' + hex(ord(m.group(0)[0]))[2:], name)
        gpo = ad_search(lh, root, 'gPCFileSysPath',
                        '(&(objectClass=groupPolicyContainer)(displayName={0}))'.format(name))
        gpos |= set([gpo[x]['gPCFileSysPath'][0] for x in gpo.keys()])

# Scan Group Policy for printer definitions.
#sd = NTSD()
printers = {}
count = len(gpos)
item = 0
for gpo in gpos:
    host, share, path = gpo[2:].split('\\', 2)
    step(23 + int(10 * item / count),
         "Processant directiva de grup '{0}'".format(path))
    with tempfile.NamedTemporaryFile() as f:
        if pool.smb_get(share,
                        '{0}\\User\\Preferences\\Printers\\Printers.xml'.format(path),
                        f.name):
            try:
                info = normalize_strings(xmltodict.parse(f.read()))
                info = safe_get(info, 'Printers', {})
                log(LOG_DEBUG, str(info))
                printers.update(printers_shared(info))
                printers.update(printers_port(info))
            except Exception as e:
                log(LOG_ERROR, "Unable to parse XML data: {0}".format(str(e)))

log(LOG_DEBUG, printers)

count = len(printers)
item = 0
for name in printers:
    step(33 + int(10 * item / count),
         "Instal·lant impressora '{0}'".format(name))
    try:
        prn.install(name, printers[name])
    except Exception as e:
        log(LOG_ERROR,
            "Installation of printer '{0}' failed: {1}".format(name, str(e)))

re_special = re.compile('\[<\s*(((?!>\]).)*)\s*>\]', re.MULTILINE)
re_action = re.compile('([a-z]+)\s*\(\s*([^)]*)\s*\)', re.IGNORECASE)

os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'

step(43, "Analizant actualitzacions")

cache = apt.Cache()
cache.update()
cache.open()
#cache.upgrade()

actions = {}
count = len(attrs['memberOf'])
item = 0
for group in attrs['memberOf']:
    step(50 + int(10 * item / count),
         "Processant grup d'aplicació '{0}'".format(group.split(',')[0][3:]))
    if group[:6].upper() == 'CN=LX_':
        log(LOG_DEBUG, "Found Linux group {0}".format(group))
        data = ad_search(lh, group, 'info')
        if data[group]['info']:
            for special in re_special.finditer(data[group]['info'][0]):
                for action in re_action.finditer(special.group(1)):
                    args = [ x.strip() for x in action.group(2).split(',')]
                    name = action.group(1).lower()
                    if name not in actions:
                        actions[name] = []
                    log(LOG_DEBUG,
                        "Adding action '{0}' with args {1}".format(name, args))
                    actions[name].append(args)

app_scripts = []
for args in actions['app'] if 'app' in actions else []:
    if len(args) < 1:
        log(LOG_ERR, "Insufficient arguments for an 'app' actions")
    else:
        app = args[0]
        log(LOG_DEBUG, "Processing app '{0}'".format(app))
        if app in cache:
            if not cache[app].is_installed:
                log(LOG_DEBUG, "Marking {0} for installation".format(app))
                cache[app].mark_install()
                if len(args) > 1:
                    log(LOG_DEBUG,
                        "Adding application script '{0}'".format(args[1]))
                    app_scripts.append(args[1])
            else:
                log(LOG_DEBUG, "Application {0} already installed".format(app))
        else:
            log(LOG_WARN, "Application {0} not available".format(app))

if len(cache.get_changes()) > 0:
    log(LOG_DEBUG, "Changes: {0}".format(cache.get_changes()))
    step(60, "Instal·lant applicacions")
    cache.commit()
    cache = apt.Cache()

step(90, "Configurant icones")

for name in glob.glob('{0}/Desktop/_imi_.*.desktop'.format(home)):
    log(LOG_DEBUG, "Deleting desktop icon {0}".format(name))
    os.remove(name)
for name in glob.glob('{0}/.local/share/applications/*.desktop'.format(home)):
    log(LOG_DEBUG, "Deleting menu icon {0}".format(name))
    os.remove(name)

re_disp = re.compile('^\s*NoDisplay\s*=\s*true\s*$',
                     re.IGNORECASE | re.MULTILINE)
icons = '{0}/applications/'.format(os.path.dirname(__file__))
if create_dir(icons):
    save_icons('/usr/share/applications', icons)
    save_icons('/usr/share/mate/applications')

for args in actions['icon'] if 'icon' in actions else []:
    if len(args) < 2:
        log(LOG_ERR, "Insufficient arguments for an 'icon' action")
    else:
        app = args[0]
        log(LOG_DEBUG, "Adding icons for '{0}'".format(app))
        if (app in cache) and cache[app].is_installed:
            avail = [ os.path.basename(x[:-8])
                        for x in cache[app].installed_files
                        if x[-8:] == '.desktop' ]
            names = avail
            log(LOG_DEBUG, "Available icons: {0}".format(avail))
            log(LOG_DEBUG, "Icon filter: {0}".format(args[2:]))
            if len(args) > 2:
                names = []
                for name in args[2:]:
                    if name in avail:
                        names.append(name)
                    else:
                        log(LOG_WARN, ("Icon '{0}' not available for "
                                       "application {1}").format(name, app))

            log(LOG_DEBUG, "Filtered list of icons: {0}".format(names))
            place = args[1].lower()
            paths = []
            if (place == 'desktop') or (place == 'all'):
                paths.append('{0}/Desktop/_imi_.'.format(home))
            if (place == 'menu') or (place == 'all'):
                paths.append('{0}/.local/share/applications/'.format(home))
            log(LOG_DEBUG, "Installation paths: {0}".format(paths))

            for path in paths:
                for name in names:
                    name += '.desktop'
                    log(LOG_DEBUG,
                        "Installing icon '{0}' to {1}".format(name, path))
                    shutil.copy(icons + name, path + name)
                    os.chmod(path + name, 0755)
        else:
            log(LOG_WARN, "Application not available")

step(95, "Executant scripts")

for script in app_scripts:
    log(LOG_DEBUG, "Running application script '{0}'".format(script))
    run_script(script)

for args in actions['script'] if 'script' in actions else []:
    if len(args) < 1:
        log(LOG_ERR, "Insufficient arguments for a 'script' action")
    else:
        log(LOG_DEBUG, "Running script '{0}'".format(args[0]))
        run_script(args[0])

