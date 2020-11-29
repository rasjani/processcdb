# -*- coding: utf-8 -*-

from .misc import is_any_windows
from .toolbase import Tool


class Clang(Tool):
    def execute(self, cdb, args):
        if not self.tool_exists():
            raise EnvironmentError(f"{self.binary} not in path, cannot execute.")

        arguments = ["--force-analyze-debug-code", f"--cdb {args.cdb}"]
        if args.xml:
            arguments.extend(["--plist"])

        if args.output is not None:
            arguments.extend([f"--output {args.output}"])

        if is_any_windows():
            arguments.extend([f"--use-analyzer {self.binary}"])

        final_command = f"{self.binary} {' '.join(arguments)}"
        return self.run(final_command)
