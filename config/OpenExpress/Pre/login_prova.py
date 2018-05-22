#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

# Llista de GPO's per mapeig d'unitats
drives_gpos = [
    'GPO-Map Drive estaticos',
    'GPO-Map Drive dinamicos'
]

# Llista d'excepcions per a polítiques d'impressió
#   Format: '<nom group': '<nom política>'
printers_gpo_mappings = {
    'GPO_UNIFLOW_COL': 'PRINT_Uniflow_IMI_COLOR',
    'GPO_UNIFLOW_BN':  'PRINT_Uniflow_IMI_BN '
}

apps_icons = {
    '/usr/share/applications/':      'common',
    '/usr/share/mate/applications/': 'mate'
}

user_icons = {
    'desktop': ['Desktop', '_imi_.'],
    'menu': ['.local/share/applications', '']
}

clean_files = [
    '.pam_environment'
]

version = '2.0'

#############################################
#                                           #
# Do not modify anything below this comment #
#                                           #
#############################################

import os
from IMI.Log import log
from IMI.Core import Core
from IMI.SMB import smb
from IMI.DNS import dns
from IMI.ADObj import ADObj
from IMI.Progress import Progress
from IMI.GPO import GPO
from IMI.Run import run
from IMI.Cfg import cfg
from IMI import Utils

from types import *
from struct import *
import sys
import re
import pwd
import tempfile
import cups
import apt
import shutil
import glob
import collections
from datetime import datetime

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

class Appliations(object):
    def __init__(self, home):
        self.home = home
        self.base = '/opt/dl/applications'
        self.re_special = re.compile('\[<\s*(((?!>\]).)*)\s*>\]', re.MULTILINE)
        self.re_action = re.compile('([a-z]+)\s*\(\s*([^)]*)\s*\)', re.IGNORECASE)
        self.re_icon = re.compile('^\s*(?:\[\s*([a-z0-9-_]+)\s*\])?\s*(.*)', re.IGNORECASE)
        self.re_NoDisplay_true = re.compile('^\s*NoDisplay\s*=\s*true\s*$', re.IGNORECASE | re.MULTILINE)
        self.re_NoDisplay_false = re.compile('^\s*NoDisplay\s*=\s*false\s*$', re.IGNORECASE | re.MULTILINE)

    def refresh(self):
        os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
        os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
        try:
            self.cache = apt.Cache()
            self.cache.update()
        except Exception as e:
            Utils.exc("Unable to update repositories", e)
            self.cache = apt.Cache()
        self.cache.open()

    def icons_mkdir(self, *path):
        try:
            path = os.path.join(self.base, *path)
            if not os.path.exists(path):
                os.mkdir(path)
            return path
        except Exception as e:
            Utils.exc("Unable to create directory '{0}'".format(path), e)
        return None

    def icons_prepare(self, iid, path='.'):
        if self.icons_mkdir(iid) is None:
            return None
        return self.icons_mkdir(iid, path)

    def icons_store(self, iid, path, prefix=''):
        try:
            log.write(log.DEBUG, "Store icons: {0} ({1}, {2})".format(path, prefix, iid))
            if iid:
                if self.icons_prepare(iid) is None:
                    return False

            path = os.path.abspath(path)
            for root, subdirs, files in os.walk(path):
                for item in files:
                    if item[-8:] != '.desktop':
                        continue

                    NoDisplay_true = False
                    NoDisplay_false = False

                    src = os.path.join(root, item)
                    with open(src, 'r') as f:
                        if self.re_NoDisplay_true.search(f.read()) is not None:
                            NoDisplay_true = True
                            log.write(log.DEBUG, "Icona {0} visible en {1}".format(item, path))
                        elif self.re_NoDisplay_false.search(f.read()) is not None:
                            NoDisplay_false = True
                            log.write(log.DEBUG, "Icona {0} oculta en {1}".format(item, path))
                        else:
                            log.write(log.DEBUG, "Icona {0} visible en {1} per omissió del paràmetre NoDisplay".format(item, path))

                    if NoDisplay_true:
                        continue
                    elif NoDisplay_false:
                        log.write(log.DEBUG, "Amagant icona {0} ...".format(src))
                        src_tmp = src + ".tmp"
                        with open(src, 'r') as f_source:
                            with open(src_tmp, 'w+') as f_temp:
                                for line in f_source:
                                    f_temp.write(line.replace("NoDisplay=false", "NoDisplay=true"))
                        os.remove(src)
                        os.rename(src_tmp, src)
                    else:
                        log.write(log.DEBUG, "Marcant icona {0} com a oculta ...".format(src))
                        src_tmp = src + ".tmp"
                        NoDisplay_trobat = False
                        with open(src, 'r') as f_source:
                            with open(src_tmp, 'w+') as f_temp:
                                for line in f_source:
                                    f_temp.write(line)
                                    if "[Desktop Entry]" in line:
                                        f_temp.write("NoDisplay=true\n")
                                        NoDisplay_trobat = True
                                if NoDisplay_trobat == False:
                                    f_temp.write("NoDisplay=true\n")
                        os.remove(src)
                        os.rename(src_tmp, src)
        except Exception as e:
            Utils.exc("Unable to store icons: {0} ({1}, {2})".format(path, prefix, iid), e)
        return None

    def icon_install(self, icon):
        if len(icon) < 2:
            log.write(log.ERR, "Insufficient arguments for an 'icon' action")
            return

        app = icon[0]
        log.write(log.DEBUG, "Adding icons for '{0}'".format(app))
        if (app not in self.cache) or not self.cache[app].is_installed:
            log.write(log.WARN, "Application not available")
            return

        avail = []
        for name in self.cache[app].installed_files:
            if not name.endswith('.desktop'):
                continue

            for location in apps_icons:
                if name.startswith(location):
                    avail.append('[{0}]{1}'.format(apps_icons[location],
                                                   os.path.relpath(name[:-8],
                                                                   location)))

        tmp = avail
        log.write(log.DEBUG, "Available icons: {0}".format(avail))
        log.write(log.DEBUG, "Icon filter: {0}".format(icon[2:]))
        if len(icon) > 2:
            tmp = []
            for name in icon[2:]:
                match = self.re_icon.match(name)
                if match is None:
                    log.write(log.ERR,
                              "Invalid icon reference: '{0}'".format(name))
                    continue
                if match.group(1) is None:
                    base = 'common'
                else:
                    base = match.group(1)
                key = '[{0}]{1}'.format(base, match.group(2))
                if key in avail:
                    tmp.append(key)
                else:
                    log.write(log.WARN, ("Icon '{0}' not available for "
                                         "application {1}").format(key, app))
        names = []
        for name in tmp:
            match = self.re_icon.match(name)
            names.append([match.group(1), match.group(2)])

        log.write(log.DEBUG, "Filtered list of icons: {0}".format(names))
        place = icon[1].lower()
        paths = []
        for location in user_icons:
            if (place == 'all') or (place == location):
                paths.append([os.path.join(self.home, user_icons[location][0]),
                              user_icons[location][1]])
        log.write(log.DEBUG, "Installation paths: {0}".format(paths))

        for path in paths:
            for data in names:
                base = data[0]
                name = data[1] + '.desktop'
                tgt = os.path.join(path[0], os.path.dirname(name),
                                   path[1] + os.path.basename(name))
                log.write(log.DEBUG,
                          "Installing icon '{0}' to {1}".format(name, tgt))
                try:
                    shutil.copy(os.path.join(self.base, base, name), tgt)
                    os.chmod(tgt, 0755)
                except Exception as e:
                    Utils.exc("Unable to install icon '{0}'".format(name), e)

    def handle_action(self, work, action, args):
        log.write(log.DEBUG, "Adding action '{0}' with args {1}".format(action, args))
        with work.lock:
            if action == 'app':
                app = args[0]
                if app in self.cache:
                    if not self.cache[app].is_installed:
                        log.write(log.DEBUG, "Marking {0} for installation".format(app))
                        self.cache[app].mark_install()
                        if len(args) > 1:
                            log.write(log.DEBUG, "Adding application script '{0}'".format(args[1]))
                            self.app_scripts.append(args[1])
                    else:
                        log.write(log.DEBUG, "Application {0} already installed".format(app))
                else:
                    log.write(log.WARN, "Application {0} not available".format(app))
            elif action == 'icon':
                self.icons.append(args)
            elif action == 'script':
                self.scripts.append(args)
            else:
                log.write(log.WARN, "Unknown action '{0}' in '{1}'".format(action, name))

    def collect(self, work, name):
        idx = work.update('Collecting applications from {0}'.format(name))

        log.write(log.DEBUG, "Found Linux group {0}".format(name))
        data = ADObj(core.ldap(), base=name, attrs=['info'])
        for special in self.re_special.finditer(data.get('info', [''])[0]):
            for action in self.re_action.finditer(special.group(1)):
                args = [x.strip() for x in action.group(2).split(',')]
                action = action.group(1).lower()
                self.handle_action(work, action, args)

        work.complete(idx)

    def process_scripts(self, work, scripts):
        for script in scripts:
            idx = work.update("Executant script {0}".format(script))
            run.script(script[0], script[1:])
            work.complete(idx)

    def install(self, work):
        changes = self.cache.get_changes()
        if len(changes) > 0:
            work.set('install', 200)

            log.write(log.DEBUG, "Installing apps: {0}".format(changes))

            try:
                self.cache.commit()
            except Exception as e:
                Utils.exc("Failed application installation", e)

            self.refresh()

        else:
            work.set('install', 0)

        work.set('appscripts', len(self.app_scripts))
        self.process_scripts(work, self.app_scripts)

        work.set('icons', len(self.icons))

        self.icons_mkdir()
        for location in apps_icons:
            self.icons_store(apps_icons[location], location)

        for icon in self.icons:
            idx = work.update("Configurant icones de '{0}'".format(icon[0]))
            self.icon_install(icon)
            work.complete(idx)

        work.set('scripts', len(self.scripts))
        self.process_scripts(work, self.scripts)

    def task_install(self, work):
        work.phase('collect', 100)
        work.phase('install', 500)
        work.phase('appscripts', 200)
        work.phase('icons', 100)
        work.phase('scripts', 300)
        work.start()

        objects = []
        for group in user.get('memberOf'):
            items = [x.split('=', 1)[1].upper() for x in group.split(',')]
            if items[0].startswith('LX_'):
                objects.append(group)

        self.refresh()

        work.set('collect', len(objects))

        self.icons = []
        self.scripts = []
        self.app_scripts = []
        for name in objects:
            core.call(None, self.collect, work, name)

        core.call_delayed(None, self.install, work)

class Printers(object):
    def __init__(self, user):
        self.cups = cups.Connection()
        self.attr = 'requesting-user-name-allowed'
        self.user = user.lower()
        self.printer_list = []
        self.maps = []
        re_driver = r'^\s*Driver\s*Name\s*:\s*\[\s*(.+[^\s])\s*\]\s*$'
        self.re_driver = re.compile(re_driver, re.IGNORECASE | re.MULTILINE)
        re_share = r'^\s*sharename\s*:\s*\[\s*(.*[^\s])\s*\]\s*$'
        self.re_share = re.compile(re_share, re.IGNORECASE | re.MULTILINE)
        re_map = re.compile(r'^(.+)=([^=]+)$')
        if run.path:
            path = os.path.join(run.path, 'drivers.map')
            with tempfile.NamedTemporaryFile() as f:
                if smb.download('SysVol', path, f.name) > 0:
                    for line in f:
                        m = re_map.match(line)
                        if m:
                            re_drv = re.compile(m.group(1).strip(),
                                                re.IGNORECASE)
                            self.maps.append([re_drv, m.group(2).strip()])

        self.refresh()

    def driver_lookup(self, name):
        for drv in self.maps:
            if drv[0].search(name):
                return drv[1]
        return None

    def get_users(self, printer):
        attrs = self.cups.getPrinterAttributes(printer, requested_attributes=[self.attr])
        if self.attr not in attrs:
            return []
        return [x.lower() for x in attrs[self.attr]]

    def refresh(self):
        self.printers = normalize_strings(self.cups.getPrinters())
        self.user_printers = []
        for printer in self.printers:
            if self.user in self.get_users(printer):
                self.user_printers.append(printer)
        log.write(log.DEBUG, "Existing printers: {0}".format(self.printers))
        log.write(log.DEBUG, "Existing printers for user {0}: {1}".format(self.user, self.user_printers))

    def resolve_printer(self, data):
        name = data['name']

        if 'path' not in data:
            log.write(log.WARN, "No path specified for printer '{0}'".format(name))
            return False

        host, printer = data['path'].strip('\\').split('\\', 1)
        if data['type'] == 'smb':
            share = smb.rpc(host, "getprinter '{0}' 2".format(printer),
                            self.re_share)
            if share == False:
                log.write(log.ERR,
                          ("Unable to resolve printer share "
                           "for '{0}'").format(name))
                return False
            data['share'] = share

        driver = smb.rpc(host, "getdriver '{0}' 1".format(printer),
                         self.re_driver)
        if driver == False:
            log.write(log.ERR, ("Unable to determine printer driver "
                                "for '{0}'".format(name)))
            return False
        ppd = self.driver_lookup(driver)
        if not ppd:
            log.write(log.ERR,
                      ("No driver mapping found for '{0}' ({1})".format(driver,
                                                                        name)))
            return False
        data['ppd'] = ppd

        return True

    def delete(self, work, name):
        idx = work.update('Deleting printer {0}'.format(name))

        users = self.get_users(name)
        log.write(log.DEBUG,
                  ("Removing printer {0} for user {1} "
                   "(users = {2})").format(name, self.user, users))
        if self.user in users:
            users.remove(self.user)
            if len(users) > 0:
                log.write(log.DEBUG, "Modifying printer {0} (users = {1})".format(name, users))
                with work.lock:
                    self.cups.setPrinterUsersAllowed(name, users)
            else:
                log.write(log.DEBUG,
                          "Deleting printer {0}".format(name))
                with work.lock:
                    self.cups.deletePrinter(name)
        else:
            log.write(log.DEBUG, "Ignoring printer {0}".format(name))

        work.complete(idx)

    def install(self, work, data):
        name = data['name']

        idx = work.update('Creating printer {0}'.format(name))

        name = name.replace(' ', '_')
        name = name.replace('/', '_')
        log.write(log.DEBUG, "Installing printer {0}".format(name))
        users = []
        if name in self.printers:
            users = self.get_users(name)
            log.write(log.DEBUG, "Printer {0} already exists (users = {1})".format(name, users))
            if self.user in users:
                log.write(log.DEBUG, "Printer {0} already prepared".format(name))
                work.complete(idx)
                return
        else:
            log.write(log.DEBUG, "Creating printer {0}".format(name))

            if not self.resolve_printer(data):
                work.complete(idx)
                return

            if data['type'] == 'ip':
                url = 'socket://{0}/{1}'.format(data['ip'], data['port'])
            elif data['type'] == 'smb':
                host = data['path'].strip('\\').split('\\')[0]
                url = 'smb://{0}/{1}'.format(host, data['share'])
            else:
                log.write(log.ERR,
                          ("Unknown type '{0}' for printer "
                           "'{1}'").format(data['type'], data['name']))
                work.complete(idx)
                return

            with work.lock:
                self.cups.addPrinter(name, ppdname=data['ppd'], info=data['comment'], location=data['location'], device=url)
                self.cups.setPrinterShared(name, False)
                self.cups.setPrinterErrorPolicy(name, 'retry-current-job')
                self.cups.setPrinterOpPolicy(name, 'authenticated')
                self.cups.enablePrinter(name)
                self.cups.acceptJobs(name)

        users.append(self.user)
        log.write(log.DEBUG, "Modifying printer {0} (users = {1})".format(name, users))
        with work.lock:
            self.cups.setPrinterUsersAllowed(name, users)

        work.complete(idx)

    def collect(self, work, name):
        idx = work.update('Collecting printers from {0}'.format(name))

        variables = {'LogonUser':smb.user}
        gpo = GPO(core.ldap(), user, ws, variables, name)
        printers = gpo.gather_printers()
        with work.lock:
            for printer in printers:
                self.printer_list.append(normalize_strings(printer))

        work.complete(idx)

    def create_all(self, work):
        self.refresh()

        work.set('create', len(self.printer_list))

        for printer in self.printer_list:
#            core.call(None, self.install, work, printer)
            self.install(work, printer)

    def task_create(self, work):
        work.phase('collect', 100)
        work.phase('create', 100)
        work.start()

        gpos = []
        for group in user.get('memberOf'):
            items = [x.split('=', 1)[1].upper() for x in group.split(',')]
            if items[0] in printers_gpo_mappings:
                gpos.append(printers_gpo_mappings[items[0]])
            elif items[0].startswith('PR'):
                gpos.append(items[0])

        work.set('collect', len(gpos))

        self.printer_list = []
        for name in gpos:
            core.call(None, self.collect, work, name)

        core.call_delayed(None, self.create_all, work)

    def task_remove(self, work):
        work.phase('delete', 100)
        work.start()

        self.refresh()

        work.set('delete', len(self.user_printers))

        for printer in self.user_printers:
#            core.call(None, self.delete, work, printer)
            self.delete(work, printer)

class Drives(object):
    def __init__(self, domain, uid, gid, home):
        self.domain = domain
        self.uid = uid
        self.gid = gid
        self.home = home
        self.drives = []

    def umount(self, path):
        log.write(log.DEBUG, "Umounting {0}".format(path))
        return run.command(['umount', path]) != False

    def dir_clean(self, path, create=False):
        log.write(log.DEBUG, "Cleaning directory {0}".format(path))
        if os.path.ismount(path):
            log.write(log.DEBUG, "Directory {0} is a mount point".format(path))
            return self.umount(path)
        if not create:
            return True
        if os.path.isdir(path):
            log.write(log.DEBUG, "Directory {0} already exists".format(path))
            return True
        if os.path.exists(path):
            log.write(log.ERR, "Entry {0} already exists and it's not a directory".format(path))
            return False
        try:
            os.mkdir(path)
        except Exception as e:
            Utils.exc("Unable to create directory {0}".format(path), e)
            return False
        log.write(log.INFO, "Directory {0} created".format(path))
        return True

    def link_clean(self):
        for name in glob.iglob(os.path.join(self.home, '?:')):
            try:
                if os.path.islink(name):
                    os.remove(name)
            except Exception as e:
                Utils.exc("Unable to delete symbolic link {0}".format(name), e)

    def create_link(self, path, link):
        log.write(log.DEBUG, "Creating link {0} -> {1}".format(link, path))
        dirname, filename = link.rsplit('/', 1)
        if os.path.islink(link):
            src = os.path.join(dirname, path)
            try:
                dst = os.path.join(dirname, os.readlink(link))
            except Exception as e:
                Utils.exc("Failed to read symbolic link {0}".format(link), e)
                return False
            if src == dst:
                log.write(log.DEBUG, "Link {0} already exists".format(link))
                return True
            log.write(log.WARN, "Link {0} points to {1}".format(link, dst))
            try:
                os.remove(link)
            except Exception as e:
                Utils.exc("Unable to remove link {0}".format(link), e)
                return False
            log.write(log.INFO, "Link {0} removed".format(link))
        if os.path.exists(link):
            log.write(log.WARN, "Entry {0} exists but it's not a link".format(link))
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
                Utils.exc("Unable to rename directory {0} to {1}".format(link, tgt), e)
                return False
        try:
            os.symlink(path, link)
        except Exception as e:
            Utils.exc("Unable to create link {0}".format(link), e)
            return False
        log.write(log.INFO, "Link {0} created".format(link))
        return True

    def mount_prepare(self, kind, name):
        path = os.path.join('/run/user', str(self.uid), self.domain)
        log.write(log.DEBUG, "Preparing mount '{0}'".format(name))
        if not self.dir_clean(path, True):
            return False
        path = os.path.join(path, kind)
        if not self.dir_clean(path, True):
            return False
        path = os.path.join(path, name)
        if not self.dir_clean(path, True):
            return False
        tgt = os.path.join(self.home, name)
        return self.create_link(path, tgt)

    def mount(self, work, drive):
        idx = work.update('Mounting drive {0}:'.format(drive['letter']))

        log.write(log.DEBUG,
                  "Mounting ({0}): {1} -> {2}/{3}:".format(self.uid,
                                                           drive['path'],
                                                           self.home,
                                                           drive['letter']))
        path = os.path.join(self.home, drive['letter'] + ':')
        if self.mount_prepare('drive', drive['letter'] + ':'):
            run.command(['mount', '-t', 'cifs', '-o',
                         'sec=krb5,cruid={0},uid={0},gid={1}'.format(self.uid,
                                                                     self.gid),
                         drive['path'].replace('\\', '/'), path])

        work.complete(idx)

    def bind(self, work, path, target):
        idx = work.update('Binding {0}'.format(target))

        log.write(log.DEBUG, "Binding {0} -> {1}".format(path, target))
        src = os.path.join('/run/user/', str(self.uid), self.domain, 'drive', path)
        dst = os.path.join('/run/user/', str(self.uid), self.domain, 'bind', target)
        if self.mount_prepare('bind', target):
            run.command(['mount', '-o', 'bind', src, dst])

        work.complete(idx)

    def delete(self, kind):
        path = os.path.join('/run/user', str(self.uid), self.domain, kind, '*')
        mounts = glob.iglob(path)
        for mount in mounts:
            self.dir_clean(mount)

    def collect(self, work, name):
        idx = work.update('Collecting drives from {0}'.format(name))

        variables = {'LogonUser':smb.user}
        gpo = GPO(core.ldap(), user, ws, variables, name)
        drives = gpo.gather_drives()
        with work.lock:
            self.drives += drives

        work.complete(idx)

    def binds(self, work):
        drive = user.get('homeDrive')
        if drive == None:
            return
        drive = drive[0]

        work.set('bind', 4)

        core.call(None, self.bind, work, os.path.join(drive, 'Dades'),
                  'Documents')
        core.call(None, self.bind, work, os.path.join(drive, 'My Videos'),
                  'Vídeos')
        core.call(None, self.bind, work, os.path.join(drive, 'My Pictures'),
                  'Imatges')
        core.call(None, self.bind, work, os.path.join(drive, 'My Music'),
                  'Música')

    def mounts(self, work):
        work.set('mount', len(self.drives))

        for drive in self.drives:
            core.call(None, self.mount, work, drive)

        core.call_delayed(None, self.binds, work)

    def task_mount(self, work):
        work.phase('collect', 100)
        work.phase('mount', 100)
        work.phase('bind', 100)
        work.start()

        work.set('collect', len(drives_gpos))

        self.drives = []
        home_url = user.get('homeDirectory')
        home_drive = user.get('homeDrive')
        if home_url and home_drive:
            self.drives.append({ 'path': home_url[0],
                                 'letter': home_drive[0][0]})

        for name in drives_gpos:
            core.call(None, self.collect, work, name)

        core.call_delayed(None, self.mounts, work)

    def task_umount(self, work):
        self.delete('bind')
        self.delete('drives')
        self.link_clean()

def work_finish(work, is_sync=False):
    work.done()
    if is_sync:
        core.sync_point_done()

def user_init():
    global user

    user = ADObj(core.ldap(), filt='(sAMAccountName={0})'.format(smb.user), extra=['tokenGroups'])

def ws_init():
    global ws

    ws = ADObj(core.ldap(), filt='(sAMAccountName={0}$)'.format(dns.host))

def is_requested(name):
    if (len(sys.argv) == 1) or ('full' in sys.argv) or (name in sys.argv):
        return True
    return False

def main():
    log.write(log.DEBUG, "Args: {0}".format(sys.argv))
    data = pwd.getpwnam(smb.user)

    progress = Progress(data.pw_uid)
    progress.start()

    printers = Printers(smb.user)
    drives = Drives(smb.domain, data.pw_uid, data.pw_gid, data.pw_dir)
    apps = Appliations(data.pw_dir)

    dc_count = len(dns.resolve(dns.domain, 'A'))
    is_login = (os.getenv('PAM_TYPE') != 'close_session') and (dc_count > 0)

    if is_login:
        for item in clean_files:
            try:
                log.write(log.DEBUG, "Removing file '{0}'".format(item))
                os.remove(os.path.join(data.pw_dir, item))
            except Exception as e:
                Utils.exc("Unable to remove file '{0}'".format(item), e)

    if is_requested('apps') and is_login:
        for location in user_icons:
            apps.icons_store(None, os.path.join(data.pw_dir, user_icons[location][0]), user_icons[location][1])

        work = progress.add('Apps', 500, "Configurant aplicacions")
        subtask = core.call_delayed(None, apps.task_install, work)
        core.call_cleanup(subtask, work_finish, work)

    if is_requested('printers'):
        work = progress.add('PrintersDel', 100, "Eliminant impressores")
        subtask = core.call_delayed(None, printers.task_remove, work)
        core.call_cleanup(subtask, work_finish, work)
        if is_login:
            work = progress.add('PrintersAdd', 200, "Creant impressores")
            subtask = core.call_delayed(subtask, printers.task_create, work)
            core.call_cleanup(subtask, work_finish, work)

    if is_requested('drives'):
        work = progress.add('DrivesDel', 100, "Eliminant unitats")
        subtask = core.call_delayed(None, drives.task_umount, work)
        core.call_cleanup(subtask, work_finish, work)
        if is_login:
            core.sync_point_add()
            work = progress.add('DrivesAdd', 100, "Creant unitats")
            subtask = core.call_delayed(subtask, drives.task_mount, work)
            core.call_cleanup(subtask, work_finish, work, True)

    if is_login:
        core.call(None, user_init)
        core.call(None, ws_init)

core = Core('login', os.getenv('PAM_SERVICE'))
if not core.ready:
    sys.exit(0)

core.start(cfg.get_int('workers', default=5), True, main)
