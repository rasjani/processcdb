# -*- coding: utf-8 -*-

from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from xml.dom import minidom
from xml.sax.saxutils import escape
from pathlib import Path
import tempfile
import os
from queue import Queue
import threading
import shutil
from .logger import LOGGER as log
from .toolbase import Tool
from .tidy_converter import OutputParser


class ClangTidy(Tool):
    def convert_arguments(self, arg):
        if arg.startswith("/"):
            return arg.replace("-", "/", 1)
        return arg

    def filter_arguments(self, args):
        def allowed_argument(arg):
            return arg[1:] not in self.config["arg_blacklist"].split(";")

        return list(filter(allowed_argument, args[1:]))

    def format_output_to_xml(self, filename, allow_dupes=True):
        def prettify(elem):
            rough_string = ElementTree.tostring(elem, "utf-8")
            reparsed = minidom.parseString(rough_string)
            return reparsed.toprettyxml(indent=" " * 4)

        def generate_verbose(items):
            x = []
            for item in items if items else []:
                x.append(f"{item.path}:{item.line}:{item.column}: {item.message}")
            return x

        def clean_rules(rules):
            seen = []
            for rule in rules:
                if rule not in seen:
                    seen.append(rule)
            return seen

        p = OutputParser()

        xml_root = Element("results")
        xml_root.set("version", "2")
        xml_cppcheck = Element("cppcheck")
        xml_cppcheck.set("version", "1.77")
        xml_root.append(xml_cppcheck)
        xml_errors = Element("errors")
        rules = []
        rules = p.parse_messages_from_file(filename)
        if not allow_dupes:
            rules = clean_rules(rules)

        for rule in rules:
            xml_error = Element("error")
            xml_error.set("id", rule.checker)
            xml_error.set("severity", "warning")
            if "modernize-" in rule.checker or "google-readability-" in rule.checker or "readability-" in rule.checker:
                xml_error.set("severity", "style")
            elif "performance-" in rule.checker:
                xml_error.set("severity", "performance")
            message = escape(f"{rule.message} (l:{rule.line},c:{rule.column})")
            xml_error.set("msg", message)
            verbose = []
            verbose.extend(generate_verbose(rule.fixits))
            verbose.extend(generate_verbose(rule.notes))

            final = escape("\n".join(filter(None, verbose)))
            if len(final) > 0:
                xml_error.set("verbose", final)

            xml_location = Element("location")
            xml_location.set("file", rule.path)
            xml_location.set("line", str(rule.line))
            xml_error.append(xml_location)
            xml_errors.append(xml_error)

        xml_root.append(xml_errors)
        with open(filename, "w") as f:
            f.write(prettify(xml_root))

    def process_queue(self, args, tmp_dir, queue):
        while True:
            cmd = queue.get()
            output = self.capture(cmd, True)
            if output[0] == "":
                output = output[1:]

            if output and tmp_dir:
                with tempfile.NamedTemporaryFile(mode="w", dir=tmp_dir, suffix=".log", delete=False) as t:
                    t.write("\n".join(output))
            queue.task_done()

    def execute(self, cdb, args):

        result = 1
        if not self.tool_exists():
            raise EnvironmentError(f"tool: {self.tool_name} not in path, cannot execute.")

        command_queue = []
        for compilation_unit in cdb:
            arguments = []

            arguments.extend(self.config["default_args"].split(";"))
            directory = Path(compilation_unit["directory"]).absolute()
            full_command = compilation_unit["command"].split(" ")
            absolute_filename = directory / compilation_unit["file"]
            compiler = Path(full_command[0]).name.lower()

            arguments.extend(self.quote_defines(self.filter_arguments(full_command[1:])))
            arguments.extend(map(lambda str: f"-I{str}", self.system_includes()))

            extra = "--quiet"
            if compiler == "cl.exe":
                arguments = list(map(self.convert_arguments, arguments))
                extra = f"{extra} --extra-arg-before=--driver-mode=cl"
                if "-EHsc" in arguments:
                    arguments.extend(["-Xclang", "-fcxx-exceptions"])  # Because clang ignores thread enabling ..

            if absolute_filename.is_file():
                if self.should_scan(absolute_filename, args.file):
                    tmp_cmd = f"cd {directory} && {self.binary} {extra} {absolute_filename} -- {' '.join(arguments)}"
                    log.debug(tmp_cmd)
                    command_queue.append(tmp_cmd)
                else:
                    log.debug(f"File {absolute_filename} is not scanned")
        try:
            tmp_dir = None
            if args.output is not None:
                tmp_dir = Path(tempfile.mkdtemp())

            tasks = self.max_tasks(args, len(command_queue))
            queue = Queue(tasks)
            for _ in range(tasks):
                thread_arguments = (args, None if not tmp_dir else str(tmp_dir), queue)
                t = threading.Thread(target=self.process_queue, args=thread_arguments)
                t.daemon = True
                t.start()
            for cmd in command_queue:
                queue.put(cmd)
            queue.join()
            if args.output is not None:
                with open(args.output, "w") as dst:
                    for name in tmp_dir.glob("*.log"):
                        dst.write(name.read_text())

                if args.xml:
                    self.format_output_to_xml(args.output, args.allow_dupes)
                shutil.rmtree(tmp_dir)
            result = 0
        except KeyboardInterrupt:
            if tmp_dir is not None:
                shutil.rmtree(tmp_dir)
            os.kill(0, 9)
        except Exception as e:  # TODO: Add proper exception handling
            log.error(f"Exception: {e} .-- ")
            result = 1

        return result
