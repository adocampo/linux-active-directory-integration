# vim: set fileencoding=utf-8 :

version = '1.0'

import __main__ as main
import sys
import os
import tempfile
import hashlib
import threading
import multiprocessing
import Queue
import random
import time
from Crypto.Hash.SHA256 import SHA256Hash

import Cfg
import Log
import SMB
import LDAP
import Run
import Utils

class Task(object):
    def __init__(self, parent, kind, mode, args = (), kwargs = {}):
        self.kind = kind
        self.args = args
        self.kwargs = kwargs
        self.delayed = []
        self.cleanup = []
        self.immediate = 1
        self.pending = 1
        self.lock = threading.Lock()
        self.parent = None
        Log.log.write(Log.DEBUG, "Created {0} {1}".format(mode, str(self)))
        if parent:
            if mode != 'cleanup':
                self.parent = parent
                parent.attach(self, mode == 'delayed')
            else:
                parent.attach_cleanup(self)

    def __str__(self):
        text = 'Task[{0},{1}]'.format(self.pending, self.immediate)
        if self.kind == 'quit':
            return "{0}('quit')".format(text)
        if self.kind == 'call':
            args = [str(x) for x in self.args[1:]]
            args += ['{0}={1}'.format(x, str(self.kwargs[x])) for x in self.kwargs]
            return "{0}('{1}', {2}({3}))".format(text, self.kind,
                                                 self.args[0].func_name,
                                                 ', '.join(args))
        return 'Task({0})'.format(self.kind)

    def attach(self, task, delayed):
        with self.lock:
            self.pending += 1
            if delayed:
                self.delayed.append(task)
            else:
                self.immediate += 1

        Log.log.write(Log.DEBUG, "Attached {0} to {1}".format(str(task),
                                                              str(self)))

    def attach_cleanup(self, task):
        with self.lock:
            self.cleanup.append(task)

    def done(self):
        Log.log.write(Log.DEBUG, "Completed {0}".format(str(self)))
        delayed = []
        with self.lock:
            self.pending -= 1
            done = self.pending == 0
            if not done and self.immediate > 0:
                self.immediate -= 1
                if self.immediate == 0:
                    delayed = self.delayed
        if done:
            delayed = self.cleanup
            if self.parent:
                delayed += self.parent.done()

            self.kind = None
            self.ldap = None
            self.args = None
            self.kwargs = None
            self.delayed = None
            self.cleanup = None
            self.immediate = 0
            self.pending = 0
            self.lock = None
            self.parent = None

        if len(delayed) > 0:
            Log.log.write(Log.DEBUG,
                          "Waking {0}".format([str(x) for x in delayed]))
        return delayed

class Core(object):
    def __init__(self, module, service, update = False):
        self.ready = False
        self.main = None
        self.module = module
        self.queue = Queue.Queue()
        self.cv = threading.Condition()
        self.event = multiprocessing.Event()
        self.event.clear()
        self.lock = threading.Lock()
        self.sync_count = 1
        self.tls = threading.local()
        self.tls.task = None
        self.tls.ldap = None

        Cfg.cfg.open(module)

        if service is None:
            service = 'interactive'
        services = Cfg.cfg.get('services', default = '').split()
        if (len(services) > 0) and (service not in services):
            return

        self.service = service

        Log.log.open(module)

        self.root = '/'
        self.main = self.module_info(main)
        self.root = os.path.join(os.path.dirname(self.main[2]), '')

        self.module_init()

        Log.log.write(Log.INFO,
                      "Starting {0} ({1})".format(module, self.main[1]))
        for mod in self.modules:
            if mod[1]:
                Log.log.write(Log.DEBUG, "Module {0} ({1})".format(mod[0],
                                                                   mod[1]))

        SMB.smb.open()

        self.base = os.path.join(SMB.smb.domain, 'scripts', 'NEOS')

        Run.run.open(self.root, self.base)

        if update:
            count = 0
            for mod in self.modules:
                count += self.module_update(mod[2])
            if count > 0:
                Log.log.write(Log.INFO, "Restarting program")
                os.execv(self.main[2], sys.argv)

        self.ready = True

    def __del__(self):
        self.close()

    def close(self):
        if self.main is not None:
            Log.log.write(Log.INFO,
                          "Finished {0} ({1})".format(self.module,
                                                      self.main[1]))

        self.event = None
        self.lock = None
        self.base = None
        self.main = None
        self.root = None
        self.modules = None
        self.module = None
        self.service = None
        self.ready = False

    def module_info(self, module):
        info = dir(module)
        if '__file__' not in info:
            return None
        path = os.path.realpath(module.__file__)
        if not path.startswith(self.root):
            return None
        if path.endswith('.pyc'):
            path = path[:-1]
        if 'version' in info:
            ver = 'v' + module.version
        else:
            ver = 'not versioned'
        return [module.__name__, ver, path]

    def module_init(self):
        imi = sys.modules['IMI']
        path = os.path.dirname(imi.__file__)
        self.modules = [self.module_info(imi)]
        for name in imi.__all__:
            mname = 'IMI.' + name
            if mname in sys.modules:
                info = self.module_info(sys.modules[mname])
            else:
                info = [mname, None, os.path.join(path, name + '.py')]
            if info:
                self.modules.append(info)

    def module_hash(self, path):
        with open(path, 'r') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def module_update(self, path):
        name = os.path.basename(path)
        if name.startswith('cached:'):
            return 0
        rel = os.path.relpath(path, self.root)
        with tempfile.NamedTemporaryFile(dir = os.path.dirname(path)) as f:
            if SMB.smb.download('SysVol', os.path.join(self.base, rel),
                                f.name) < 1:
                return 0
            pre = self.module_hash(path)
            post = self.module_hash(f.name)
            if pre != post:
                os.remove(path)
                os.link(f.name, path)
                os.chmod(path, 0700)
                Log.log.write(Log.INFO, "{0} has been updated".format(name))
                return 1
        return 0

    def safe_run(self, func, args = (), kwargs = {}):
        Log.log.write(Log.DEBUG,
                      "Running task {0}({1}, {2})".format(func.func_name,
                                                          args, kwargs))
        try:
            func(*args, **kwargs)
        except Exception as e:
            Utils.exc(("Execution failed, Func = {0}, Args = {1}, "
                       "KWArgs = {2}").format(func.func_name, args, kwargs), e)

    def submit(self, task):
        with self.cv:
            if self.queue.empty():
                self.cv.notify()
            self.queue.put(task)

    def call(self, parent, func, *args, **kwargs):
        if not parent:
            parent = self.tls.task
        task = Task(parent, 'call', 'immediate', (func,) + args, kwargs)
        self.submit(task)

    def call_delayed(self, parent, func, *args, **kwargs):
        if not parent:
            parent = self.tls.task
        return Task(parent, 'call', 'delayed', (func,) + args, kwargs)

    def call_cleanup(self, parent, func, *args, **kwargs):
        if not parent:
            parent = self.tls.task
        Task(parent, 'call', 'cleanup', (func,) + args, kwargs)

    def completed(self, task):
        tasks = task.done()
        for task in tasks:
            self.submit(task)

    def worker(self):
        Log.log.write(Log.DEBUG, "Starting worker")

        seed = SHA256Hash(str(threading.current_thread().ident)).hexdigest()
        random.seed(seed)

        self.tls.ldap = LDAP.LDAP(SMB.smb.domain)

        kind = ''

        self.cv.acquire()

        while kind != 'quit':
            while self.queue.empty():
                self.cv.wait()
            task = self.queue.get()
            self.cv.release()

            kind = task.kind
            if kind == 'call':
                func = task.args[0]
                self.tls.task = task
                self.safe_run(task.args[0], task.args[1:], task.kwargs)

            self.completed(task)

            self.cv.acquire()

            self.queue.task_done()

        self.cv.release()

        self.tls.ldap.close()
        self.tls.ldap = None
        self.tls.task = None

        self.submit(Task(None, 'quit', 'immediate'))

        Log.log.write(Log.DEBUG, "Worker terminated")

    def ldap(self):
        return self.tls.ldap

    def sync_point_add(self):
        with self.lock:
            self.sync_count += 1
        Log.log.write(Log.DEBUG, "Added sync point")

    def sync_point_done(self):
        with self.lock:
            self.sync_count -= 1
            if self.sync_count == 0:
                self.event.set()
        Log.log.write(Log.DEBUG, "Completed sync point")

    def start(self, count, background, func, *args, **kwargs):
        pid = os.fork()
        if pid == 0:
            workers = []
            for _ in range(count):
                worker = threading.Thread(target = self.worker)
                worker.start()
                workers.append(worker)

            task = Task(None, 'call', 'immediate', (func,) + args,
                        kwargs)
            self.call_delayed(task, self.sync_point_done)
            self.submit(task)

            self.queue.join()
            self.submit(Task(None, 'quit', 'immediate'))

            for worker in workers:
                worker.join()

            return

        if background:
            if self.event.wait(Cfg.cfg.get_int('timeout', default = 20)):
                Log.log.write(Log.DEBUG, "Detached from main process")
            else:
                Log.log.write(Log.WARN,
                              "Timed out waiting for main process detach")
        else:
            os.waitpid(pid, 0)

        os._exit(0)
