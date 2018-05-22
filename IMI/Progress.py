# vim: set fileencoding=utf-8 :

version = '1.0'

import threading
from collections import OrderedDict

import Log
import Utils

class Work(object):
    def __init__(self, progress, name, weight, msg):
        self.progress = progress
        self.name = name
        self.msg = msg
        self.value = 0
        self.weight = weight
        self.total = 0
        self.last = 0
        self.phases = {}
        self.phase_weight = 0
        self.current = None
        self.key = 0
        self.msgs = OrderedDict()
        self.lock = threading.Lock()

    def phase(self, name, weight):
        self.phases[name] = [weight, 0, 0, 0]
        self.phase_weight += weight

    def start(self):
        self.total = sum([self.phases[x][0] for x in self.phases])
        Log.log.write(Log.DEBUG,
                      "Starting work '{0}' ({1})".format(self.name,
                                                         self.total))

    def set(self, name, total):
        self.current = name
        with self.lock:
            self.phases[name][1] = total
            self.phases[name][2] = 0
        Log.log.write(Log.DEBUG,
                      "Starting phase '{0}.{1}' ({2})".format(self.name, name,
                                                              total))

    def update(self, msg, count = 1):
        with self.lock:
            idx = self.key
            self.key += 1
            self.msgs[idx] = msg

            Log.log.write(Log.DEBUG,
                          "Step {0}.{1}: {2}".format(self.name,
                                                     self.current, msg))

        self.progress.update(self, 0, msg)

        return idx

    def complete(self, idx, count = 1):
        delta = 0

        with self.lock:
            msg = None
            keys = self.msgs.keys()
            oldmsg = self.msgs.pop(idx)
            if keys.pop() == idx:
                if len(keys) > 0:
                    msg = self.msgs[keys[-1]]

            weight = self.phases[self.current][0]
            total = self.phases[self.current][1]
            current = self.phases[self.current][2] + count
            last = self.phases[self.current][3]
            if current > total:
                current = total
            done = int(current * weight / total)
            if last != done:
                delta = done - last
                self.phases[self.current][3] = done
            self.phases[self.current][2] = current

            done = done * 100 / weight
            Log.log.write(Log.DEBUG,
                          "Done {0}.{1}({2}%): {3}".format(self.name,
                                                           self.current,
                                                           done, oldmsg))

            self.value += delta
            delta = 0
            done = int(self.value * self.weight / self.total)
            if self.last != done:
                delta = done - self.last
                self.last = done

        self.progress.update(self, delta, msg)

    def done(self):
        Log.log.write(Log.DEBUG, "Finishing work '{0}'".format(self.name))
        self.progress.unbind(self)
        self.progress = None
        self.lock = None
        self.msgs = None

class Progress(object):
    def __init__(self, uid):
        self.value = 0
        self.total = 0
        self.count = 0
        self.complete = 0
        self.works = []
        self.lock = threading.Lock()
        self.last = 'Inicialitzant'
        name = '/tmp/login_{0}'.format(uid)
        try:
            self.file = open(name, 'ab+', 0)
        except Exception as e:
            Utils.exc("Unable to open progress file '{0}'".format(name), e)
            self.file = None
        self.write(self.last)

    def close(self):
        self.value = None
        self.total = None
        self.count = None
        self.complete = None
        self.works = []
        self.lock = None
        if self.file:
            self.file.close()
            self.file = None

    def add(self, name, weight, msg):
        work = Work(self, name, weight, msg)
        self.bind(work)
        return work

    def write(self, text):
        if not self.file:
            return
        progress = self.value * 100 / (self.total if self.total else 1)
        try:
            self.file.write("{0}\n# {1}\n".format(progress, text))
        except Exception as e:
            Utils.exc("Step notify failed", e)

    def show(self, text):
        if text is None:
            text = self.last
        self.last = text
        self.write("[{0}/{1}] {2}".format(self.complete, self.count, text))

    def bind(self, work):
        with self.lock:
            self.count += 1
            self.total += work.weight
            self.works.append(work)

    def unbind(self, work):
        with self.lock:
            self.complete += 1
            self.works.remove(work)
            self.value += work.weight - work.last
            msg = None
            if len(self.works) == 0:
                msg = "Completed"

            self.show(msg)

    def start(self):
        self.count = len(self.works)
        self.show("Inicialitzant")

    def update(self, work, delta, msg):
        with self.lock:
            self.value += delta
            self.works.remove(work)
            self.works.insert(0, work)

            self.show(msg)
