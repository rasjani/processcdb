# -*- coding: utf-8 -*-

from .misc import is_any_windows, capture_output
import multiprocessing
import subprocess
import configparser
import os
from pathlib import Path
from .logger import LOGGER as log
import shutil
import shlex


class Tool(object):
    tool_name = ""
    capture = staticmethod(capture_output)

    def default_config(self):
        cfg = configparser.ConfigParser()
        cfg[self.tool_name] = {
            "binary": self.tool_name,
            "file_blacklist": "",
            "arg_blacklist": "",
            "jobs": 0,
            "system_includes": "",
            "default_args": "",
        }
        return cfg[self.tool_name]

    def _set_defaults(self, config):
        self.config = self.default_config()
        if config and self.tool_name in config:
            section = config[self.tool_name]
            for key in section.keys():
                self.config[key] = section[key]

    def __init__(self, tool_name, tool_config=None):
        self.tool_name = tool_name
        self.config = {}
        self._set_defaults(tool_config)

    @property
    def prevent_scan(self):
        if self.config and "file_blacklist" in self.config:
            return list(filter(None, self.config["file_blacklist"].split(";")))
        return []

    @property
    def binary(self):
        tool_name = self.tool_name
        if "binary" in self.config and self.config["binary"]:
            tool_name = self.config["binary"]

        if is_any_windows():
            if " " in tool_name:
                tool_name = f'"{tool_name}"' ## Why oh why doesnt shlex.quote() use " on windows wtf?
        else:
            tool_name = shlex.quote(tool_name)
        return tool_name


    def max_tasks(self, args, total_tasks=0):
        default_jobs = int(self.config["jobs"])
        cpu_count = multiprocessing.cpu_count()
        if args.jobs != 0:
            default_jobs = args.jobs

        if default_jobs == 0:
            default_jobs = cpu_count

        if total_tasks > 0 and total_tasks < cpu_count:
            return total_tasks
        if default_jobs > cpu_count:
            log.warning(f"Requesting {default_jobs} concurrent processing jobs is higher than current {cpu_count} core count ")
        return default_jobs

    def system_includes(self):
        def clean(str):
            return str.replace("(framework directory)", "").strip()

        includes = []
        includes_from_config = self.config["system_includes"]

        if includes_from_config == "env":
            includes = os.environ.get("INCLUDE", "").split(";")
        elif includes_from_config == "detect" and not is_any_windows():
            results = self.capture("clang -x c++ -v -E /dev/null")
            sidx = results.index("#include <...> search starts here:") + 1
            eidx = results.index("End of search list.")
            includes = map(lambda str: clean(str), results[sidx:eidx])
        else:
            includes = includes_from_config.split(";")

        return filter(None, includes)

    def tool_exists(self):
        return shutil.which(self.config["binary"]) is not None

    def quote_defines(self, args):
        # TODO: Maybe use shlex.quote here ?
        def fix(str):
            if str.startswith("-D"):
                return str.replace('"', '\\"')
            else:
                return str

        return map(lambda arg: fix(arg), args)

    def should_scan(self, filename, files):
        # Needs a rewrite
        res = False
        patterns = files if isinstance(files, list) else [files]
        blacklisted = any(filename.match(pattern) for pattern in self.prevent_scan)
        requested = any(filename.match(str(pattern)) for pattern in patterns)
        if requested:
            if blacklisted:
                log.debug(f"File {filename} is blacklisted but requested to be scanned.")
            res = True
        else:
            if not patterns and not blacklisted:
                res = True
        return res

    def execute(self, cdb, args=None):
        return None

    def run(self, command_line):
        log.debug(f"RUN: {command_line}")
        return subprocess.call(command_line, shell=True)
