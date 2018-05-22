# vim: set fileencoding=utf-8 :

version = '1.0'

import platform
import random
from dns import resolver

import Log
import Run
import Utils

class DNS(object):
    def __init__(self):
        self.cache = {}
        self.host, self.domain = platform.node().split('.', 1)

    def peek(self, name, rectype):
        name = name.lower()
        if name not in self.cache:
            self.cache[name] = {}
        entries = self.cache[name]
        if rectype not in entries:
            entries[rectype] = []
        return list(entries[rectype])

    def shuffle(self, entries):
        count = len(entries)
        if count > 0:
            idx = random.randint(0, count - 1)
            entries = entries[idx:] + entries[:idx]
        return entries

    def get(self, name, rectype):
        name = name.lower()
        entries = self.peek(name, rectype)
        alive = []
        for entry in entries:
            if Run.run.command(['ping', '-c', '1', '-W', '1', entry]) != False:
                alive.append(entry)
            else:
                Log.log.write(Log.WARN,
                              ("Host {0} seems to be down "
                               "or it's slow").format(entry))
        self.cache[name][rectype] = alive
        return self.shuffle(alive)

    def decode(self, record, rectype):
        if rectype == 'SRV':
            return record.target.to_text(True).lower()
        if rectype == 'A':
            return record.address
        return None

    def resolve(self, name, rectype):
        name = name.lower()
        entries = self.peek(name, rectype)
        if len(entries) > 0:
            return self.shuffle(entries)
        try:
            entries = resolver.query(name, rectype)
        except Exception as e:
            Utils.exc("Failed to quert DNS for '{0}'".format(name), e)
            entries = []
        result = []
        for entry in entries:
            data = self.decode(entry, rectype)
            if data:
                result.append(data)
        self.cache[name][rectype] = result
        return self.get(name, rectype)

    def bad(self, name, rectype, value):
        name = name.lower()
        entries = self.get(name, rectype)
        if value in entries:
            self.cache[name][rectype].remove(value)

dns = DNS()
