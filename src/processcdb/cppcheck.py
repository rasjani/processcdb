# -*- coding: utf-8 -*-

from .toolbase import Tool
import os
import tempfile
import configparser
from pathlib import Path


class CppCheck(Tool):

    def default_config(self):
        cfg = configparser.ConfigParser()
        cfg[self.tool_name] = {
            "binary": self.tool_name,
            "file_blacklist": "",
            "jobs": 0,
            "system_includes": "",
            "supression_file": "",
            "default_args": "",
        }
        return cfg[self.tool_name]

    def suppression_file(self):
        if "suppression_file" in self.config and self.config["suppression_file"]:
            supp = Path(self.config["suppression_file"])
            if supp.exists():
                return str(supp.absolute())
        return None

    def includes(self, args):
        return filter(lambda arg: "-i" in arg, args[1:-1])

    def execute(self, cdb, args):
        result = 1
        if not self.tool_exists():
            raise EnvironmentError(f"tool: {self.tool_name} not in path, cannot execute.")

        all_includes = []
        all_sources = []
        for compilation_unit in cdb:
            directory = compilation_unit["directory"]
            temp_name_sources = None
            temp_name_includes = None
            filename = compilation_unit["file"]
            absolute_filename = (Path(directory) / filename).absolute()
            if os.path.isfile(absolute_filename) and self.should_scan(absolute_filename, args.file):
                all_includes.extend(self.includes(compilation_unit["command"]))
                all_sources.append(absolute_filename)

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as t:
            try:
                temp_name_includes = t.name
                for line in list(set(all_includes)):
                    t.write(f"{line[:2]}\n")
                for line in self.system_includes():
                    t.write(f"{line}\n")
            except:
                pass

            total_files = 0
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as t:
                temp_name_sources = t.name
                for line in all_sources:
                    t.write(f"{line}\n")
                    total_files += 1

                arguments = [
                    f"--includes-file={temp_name_includes}",
                    f"--file-list={temp_name_sources}",
                    f"-j {self.max_tasks(args, total_files)}",
                ]
                arguments.extend(self.config["default_args"].split(";"))
                suppressions = self.suppression_file()
                if suppressions:
                    arguments.append(f"--suppressions-list={suppressions}")

                if args.xml:
                    arguments.extend(["--xml", "--xml-version=2"])

                if os.path.isfile(temp_name_includes) and os.path.isfile(temp_name_sources):
                    tmp_cmd = f"{self.binary} {' '.join(arguments)}"
                    if args.output is not None:
                        final_command = f"{tmp_cmd} 2> {args.output}"
                    else:
                        final_command = tmp_cmd

                    result = self.run(final_command)

        return result
