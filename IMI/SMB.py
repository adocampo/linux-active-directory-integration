# vim: set fileencoding=utf-8 :

version = '1.0'

import os
import gssapi

import Log
import DNS
import Run
import Utils

class SMB(object):
    def __init__(self):
        self.kerberos = False
        self.realm = None
        self.domain = None
        self.user = None
        self.dc = None

    def __del__(self):
        self.close()

    def open(self):
        self.kerberos = False
        self.domain = DNS.dns.domain
        self.user = os.getenv('PAM_USER')
        if not self.user:
            self.user = os.getenv('USER')

        try:
            cred = gssapi.Credentials(usage='initiate')
            if cred.name is None:
                Log.log.write(Log.WARN, "No GSS user credentials found");
                return
        except gssapi.raw.misc.GSSError as e:
            Utils.exc("Unable to get user credentials", e)
            return

        id = str(cred.name)
        if '@' not in id:
            Log.log.write(Log.ERR, "Invalid user credentials ({0})".format(id))
            return

        self.user, self.realm = id.split('@', 1)
        self.domain = self.realm.lower()
        self.kerberos = True

    def close(self):
        self.kerberos = False
        self.realm = None
        self.domain = None
        self.user = None
        self.dc = None

    def execute(self, host, share, command):
        Log.log.write(Log.DEBUG,
                      ("Executing smbclient command '{0}' "
                       "on {1}/{2}").format(command, host, share))

        if len(DNS.dns.resolve(host, 'A')) == 0:
            Log.log.write(Log.ERR, "Unable to resolve host {0}".format(host))
            return 0

        unc = '//{0}/{1}'.format(host, share)
        if Run.run.command(['smbclient', unc,
                            '-E', '-k', '-c', command]) != False:
            Log.log.write(Log.DEBUG, "smbclient command completed successfully")
            return 1

        Log.log.write(Log.WARN, "smbclient command failed")
        return -1

    def execute_all(self, share, command):
        if self.dc:
            Log.log.write(Log.DEBUG, "Reusing server {0}".format(self.dc))
            ret = self.execute(self.dc, share, command)
            if ret != 0:
                return ret

        hosts = DNS.dns.resolve('_ldap._tcp.dc._msdcs.{0}'.format(self.domain),
                                'SRV')
        for host in hosts:
            Log.log.write(Log.DEBUG, "Trying server {0}".format(host))

            ret = self.execute(host, share, command)
            if ret != 0:
                self.dc = host
                return ret

        self.dc = None

        Log.log.write(Log.WARN, ("Unable to execute the smbclient command "
                                 "on any domain controller"))
        return 0

    def dir_exists(self, path):
        Log.log.write(Log.DEBUG, "Checking directory '{0}'".format(path))
        return self.execute_all('SysVol', 'cd {0}'.format(path))

    def download(self, share, src, dst):
        Log.log.write(Log.DEBUG,
                      "Downloading {0}/{1} to {2}".format(share, src, dst))

        command = ''
        name = src
        if '/' in name:
            path, name = name.rsplit('/', 1)
            command = 'cd {0}; '.format(path)
        command += 'get {0} {1}'.format(name, dst)
        return self.execute_all(share, command)

    def rpc(self, host, command, pattern = None):
        Log.log.write(Log.DEBUG, ("Executing rpcclient command '{0}' "
                                  "on {1}").format(command, host))

        if len(DNS.dns.resolve(host, 'A')) == 0:
            Log.log.write(Log.ERR, "Unable to resolve host {0}".format(host))
            return False

        out = Run.run.command(['rpcclient', '-k', '-c', command, host])
        if out == False:
            Log.log.write(Log.WARN, "rpcclient command failed")
            return False

        Log.log.write(Log.DEBUG, "rpcclient command completed successfully")

        if pattern:
            match = pattern.search(out)
            if match is None:
                Log.log.write(Log.DEBUG,
                              ("rpcclient didn't return the expected "
                               "data for '{0}'").format(command))
                return False
            out = match.group(1)
            Log.log.write(Log.DEBUG,
                          "rpcclient filtered data: '{0}'".format(out))
        return out

smb = SMB()
