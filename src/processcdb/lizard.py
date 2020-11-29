# -*- coding: utf-8 -*-

from .toolbase import Tool
import tempfile
import os


class Lizard(Tool):
    def execute(self, cdb, args):
        result = 1
        temp_name = None
        if not self.tool_exists():
            raise EnvironmentError(f"tool: {self.tool_name} not in path, cannot execute.")

        total_files = 0
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as t:
            temp_name = t.name
            for compilation_unit in cdb:
                directory = compilation_unit["directory"]
                filename = compilation_unit["file"]
                absolute_filename = os.path.abspath(os.path.join(directory, filename))
                if os.path.isfile(absolute_filename) and self.should_scan(absolute_filename, args.file):
                    t.write(f"{absolute_filename}\n")
                    total_files += 1

            if os.path.isfile(temp_name):
                arguments = [
                    "-l cpp",
                    "--ignore_warnings -1",
                    f"--working_threads {self.max_tasks(args, total_files)}",
                    f"--input_file {temp_name} -ENS",
                ]
                if args.xml:
                    arguments.extend(["--xml"])

                tmp_cmd = f"lizard {' '.join(arguments)}"
                if args.output is not None:
                    final_command = f"{tmp_cmd} > {args.output}"
                else:
                    final_command = tmp_cmd
                result = self.run(final_command)

            return result
