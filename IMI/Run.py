# vim: set fileencoding=utf-8 :

version = '1.0'

import os
import subprocess
import tempfile

import Cfg
import Log
import DNS
import SMB
import Utils

class Run(object):
    def __init__(self):
        self.root = None
        self.base = None
        self.location = None
        self.path = None

    def __del__(self):
        self.close()

    def open(self, root, base):
        self.root = root
        self.base = None
        self.location = [
                            [ 'host', DNS.dns.host],
                            [ 'config', Cfg.cfg.wsclass, Cfg.cfg.wsenv]
                        ]
        for location in self.location:
            path = os.path.join(base, *location)
            if SMB.smb.dir_exists(path) > 0:
                self.base = base
                self.location = location
                self.path = path
                return
        Log.log.write(Log.ERR,
                      "Scripts location not found. Running in local mode")

    def close(self):
        self.root = None
        self.base = None
        self.location = None
        self.path = None

    def command(self, cmd):
        Log.log.write(Log.DEBUG, "Executing command: {0}".format(cmd))

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            out, err = proc.communicate()
        except Exception as e:
            Utils.exc("Execution of '{0}' failed".format(cmd[0]), e)
            return False

        Log.log.write(Log.DEBUG, "cmd.out = {0}".format(out))
        Log.log.write(Log.DEBUG, "cmd.err = {0}".format(err))

        if proc.returncode != 0:
            Log.log.write(Log.ERR,
                          ("Command returned error {0}: {1} "
                           "({2} {3})").format(proc.returncode, cmd[0], out,
                                               err))
            return False

        return out

    def script_process(self, path, args):
        try:
            os.chmod(path, 0700)
            cmd = [path]
            cmd.extend(args)
            if self.command(cmd) != False:
                return 1
        except Exception as es:
            Utils.exc("Unable to execute script '{0}'".format(path), e)
        return -1

    def script_download(self, is_temp, path, local, args):
        ret = 0
        if path:
            ret = SMB.smb.download('SysVol', path, local)
        if (ret == 0) and not is_temp and os.path.exists(local):
            ret = 1
        if (ret > 0) and not self.script_process(local, args):
            ret = -1
        if (ret < 0) and not is_temp and os.path.exists(local):
            Log.log.write(Log.DEBUG,
                          "Removing cached script '{0}'".format(local))
            os.remove(local)
        return ret

    def script_run(self, remote, location, name, args):
        local = 'cached:{0}:{1}'.format(':'.join(location), name)
        local = os.path.join(os.path.dirname(self.root), local)
        return self.script_download(False, remote, local, args)

    def script(self, name, args = [], cache = False):
        remote = None
        if self.path:
            remote = os.path.join(self.path, name)
        if cache:
            if not remote:
                ret = 0
                for location in self.location:
                    ret = self.script_run(remote, location, name, args)
                    if ret != 0:
                        break
                return ret
            else:
                return self.script_run(remote, self.location, name, args)
        with tempfile.NamedTemporaryFile() as f:
            f.file.close()
            return self.script_download(True, remote, f.name, args)

run = Run()
