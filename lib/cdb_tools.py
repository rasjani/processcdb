#!/usr/bin/env python

import os
import subprocess
import tempfile
from tidy_converter import OutputParser
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from xml.dom import minidom
from xml.sax.saxutils import escape
import multiprocessing
import Queue
import threading
import glob
import shutil

extras_imported = True
try:
  from whatthepatch import parse_patch
  from git import Repo
except:
  extras_imported = False



def is_any_windows():
    return is_windows() or is_cygwin()

def is_mac():
    if 'Darwin' in platform.system():
        return True
    return False

def capture_output(args, captureErr = True):
    if captureErr:
        return subprocess.check_output(args,shell=True, stderr=subprocess.STDOUT).split('\n')
    else:
        return subprocess.check_output(args,shell=True).split('\n')


def remove_untouched_files(cdb, commits):
    def modified_lines(data):
        return data[0] == None and data[1] != None
    def line_numbers(data):
        return data[1]

    if not extras_imported:
        print("pip -r requirements.txt is required to run this portion of the code")
        return cdb

    patch = None
    repo = Repo("../..")

    try:
        patch = parse_patch(repo.git.diff(commits[0],commits[1]))
    except:
        patch = parse_patch(repo.git.diff("{0}^".format(commits[0])))

    new_cdb = []
    base_dir = os.path.dirname(repo.git_dir)
    lookup = {}
    for i in cdb:
        current = os.path.abspath(os.path.join(i['directory'], i['file']))
        lookup[current] = i
    for diff in patch:
        fullname = os.path.abspath(os.path.join(base_dir, diff.header.new_path))
        if fullname in lookup:
            cdb_entry = lookup[fullname]
            cdb_entry['changes_rows'] = map(line_numbers, filter(modified_lines, diff.changes))
            new_cdb.append(cdb_entry)
    return new_cdb

def remove_dupes(cdb):
    seen = []
    new_cdb = []
    for i in cdb:
        current = os.path.abspath(os.path.join(i['directory'], i['file']))
        if not current in seen:
            new_cdb.append(i)
            seen.append(current)
    return new_cdb

class Tool(object):
    tool_name = ""
    capture = staticmethod(capture_output)

    def __init__(self, tool_name):
        self.tool_name = tool_name
        self.prevent_scan = self.blacklist()

    def blacklist(self):
        blacklist = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "blacklist.txt"))
        buffer=[".qtquickcompiler","moc_","qrc_"]
        try:
            with open(blacklist,'r') as f:
                buffer.extend(map(lambda str: str.strip(), f.readlines()))
        except:
            pass

        return buffer


    def max_tasks(self,args):
        return args.jobs if args.jobs != 0 else multiprocessing.cpu_count()

    def system_includes(self):
        def clean(str):
            return str.replace('(framework directory)','').strip()

        includes = []
        if is_any_windows():
            try:
                includes = os.environ["INCLUDE"].split(';')
            except:
                pass
        else:
            results = self.capture('clang -x c++ -v -E /dev/null')
            sidx = results.index('#include <...> search starts here:') + 1
            eidx = results.index('End of search list.')
            includes = map(lambda str: clean(str), results[sidx:eidx])
        return filter(None,includes)

    def tool_exists(self):
        def really_exists(tool):
            return any(os.access(os.path.join(path, tool), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))

        base, ext = os.path.splitext(self.tool_name)
        if is_any_windows() and (not ext or len(ext) == 0):
          base, ext = os.path.splitext(self.tool_name)
          for ext in os.environ['PATHEXT'].split(';'):
            if really_exists("{t}{e}".format(t=self.tool_name, e=ext)):
              return True
        return really_exists(self.tool_name)

    def filter_arguments(self,args):
        return filter(lambda arg: arg not in blacklisted_keywords, args[1:-1])

    def quote_defines(self, args):
        def fix(str):
          if str.startswith('-D'):
              return str.replace('"','\\"')
          else:
              return str
        return map(lambda arg:  fix(arg), args)

    def should_scan(self,filename, args):
        if len(args.file)>0:
            return filename in args.file # and (not any(frac in filename for frac in self.prevent_scan))
        else:
            return not any(frac in filename for frac in self.prevent_scan)

    def execute(self,cdb, args = None):
        return None

    def run(self, command_line, debug = False):
        if debug:
          print "RUN: {x}".format(x=command_line)
        return subprocess.call(command_line,shell = True)

class ClangTidy(Tool):
    def filter_arguments(self,args):
        blacklisted_keywords = [
            # TODO: Make these configurable from shell ..
            '-MDd',
            '-Zi',
            '-Zc:strictStrings',
            '-Zc:throwingNew',
            '-Zc:wchar_t',
            '-GR',
            '-W3',
            '-w34100',
            '-w34189',
            '-w44996',
            '-w44456',
            '-w44457',
            '-w44458',
            '-wd4577',
            '-wd4467',
            '-Yupch.h',
            '-FIupch.h',
            '/FItime.h'
        ]
        return filter(lambda arg: arg not in blacklisted_keywords, args[1:-1])

    def format_output_to_xml(self,filename, allow_dupes = True):
        def prettify(elem):
            rough_string = ElementTree.tostring(elem, 'utf-8')
            reparsed = minidom.parseString(rough_string)
            return reparsed.toprettyxml(indent="    ")
        def generate_verbose(items):
            x = []
            for item in items if items else []:
                x.append("{fnam}:{line}:{column}: {msg}".format(fnam=item.path, line=item.line, column=item.column, msg=item.message))
            return x
        def clean_rules(rules):
            seen = []
            for rule in rules:
                if not rule in seen:
                    seen.append(rule)
            return seen

        p = OutputParser()

        xml_root = Element('results')
        xml_root.set('version', '2')
        xml_cppcheck = Element('cppcheck')
        xml_cppcheck.set('version','1.77')
        xml_root.append(xml_cppcheck)
        xml_errors = Element('errors')
        rules = []
        rules = p.parse_messages_from_file(filename)
        if not allow_dupes:
            rules = clean_rules(rules)

        for rule in rules:
            if rule.path_miss:
                continue
            xml_error = Element('error')
            xml_error.set('id',rule.checker)
            xml_error.set('severity',rule.severity)
            if "modernize-" in rule.checker or "google-readability-" in rule.checker or "readability-" in rule.checker:
                xml_error.set('severity','style')
            elif "performance-" in rule.checker:
                xml_error.set('severity','performance')
            else:
                xml_error.set('severity',rule.severity)
            message  = escape("{msg} (l:{l},c:{c})".format(msg = rule.message, c = rule.column, l = rule.line))
            xml_error.set('msg',message)
            verbose = []
            verbose.extend(generate_verbose(rule.fixits))
            verbose.extend(generate_verbose(rule.notes))

            final = escape("\n".join(filter(None,verbose)))
            if len(final)>0:
              xml_error.set('verbose',final)

            xml_location = Element('location')
            xml_location.set('file',rule.path)
            xml_location.set('line',str(rule.line))
            xml_error.append(xml_location)
            xml_errors.append(xml_error)

        xml_root.append(xml_errors)
        with open(filename,"w") as f:
            f.write(prettify(xml_root))

    def process_queue(self, args, tmp_dir, queue):
        while True:
            cmd = queue.get()
            if tmp_dir != None:
                with tempfile.NamedTemporaryFile(mode='w', dir = tmp_dir, suffix='.log',delete=False) as t:
                    t.write("\n".join(self.capture(cmd,False)))
            else:
                self.run(cmd)
            queue.task_done()

    def execute(self,cdb, args):
        result = 1
        if self.tool_exists():
            command_queue = []
            for compilation_unit in cdb:
                directory = compilation_unit['directory']
                arguments = []
                if is_mac():
                    # for some reason atleast clang-tidy fails to parse the
                    # cl_platform.h and its dependencies if SSE instruction
                    # sets are on, so, just get rid of those for now ..
                    arguments.extend(['-U__SSE__','-U__SSE2__','-UTARGET_CPU_X86','-UTARGET_CPU_X86_64'])
                arguments.extend(self.quote_defines(self.filter_arguments(compilation_unit['arguments'])))
                arguments.extend(map(lambda str: "-I{s}".format(s=str), self.system_includes()))
                filename = compilation_unit['file']
                absolute_filename = os.path.abspath(os.path.join(directory, filename))
                if os.path.isfile(absolute_filename) and self.should_scan(absolute_filename,args):
                    final_command = ""
                    tmp_cmd = "cd {pwd} && clang-tidy {filename} -- {args}".format(pwd = directory, filename = absolute_filename, args = " ".join(arguments))
                    """
                    if args.output != None:
                        final_command = "{x} >> {y}".format(x = tmp_cmd, y = args.output)
                    else:
                        final_command = tmp_cmd
                    """
                    command_queue.append(tmp_cmd)
                    #result = self.run(final_command)
            tmpDir=None
            try:
                tmp_dir = None
                if args.output != None:
                    tmp_dir=tempfile.mkdtemp()

                tasks = self.max_tasks(args)
                queue = Queue.Queue(tasks)
                for _ in range(tasks):
                    t = threading.Thread(target=self.process_queue, args=(args,tmp_dir,queue))
                    t.daemon = True
                    t.start()
                for cmd in command_queue:
                    queue.put(cmd)
                queue.join()
                if args.output != None:
                    with open(args.output,"w") as dst:
                        for name in glob.glob(os.path.join(tmp_dir,"*.log")):
                            with open(name,"r") as src:
                                buffer = src.readlines()
                                dst.write("".join(buffer))

                    if args.xml:
                        self.format_output_to_xml(args.output, args.allow_dupes)
                    shutil.rmtree(tmp_dir)
                result = 0
            except KeyboardInterrupt:
                if tmp_dir != None:
                    shutil.rmtree(tmp_dir)
                os.kill(0,9)
            except Exception as e:
                result = 1



        else:
            raise EnvironmentError("tool: {tool} not in path, cannot execute.".format(tool = self.tool_name))

        return result


class Clang(Tool):
    def execute(self, cdb, args):
      result = 1
      winsee_clang_path = "C:\\apps\\clang\\bin\\clang.exe"
      if self.tool_exists():
          arguments = ["--force-analyze-debug-code",
                      "--cdb {f}".format(f = args.cdb)]
          if args.xml == True:
              arguments.extend(["--plist"])

          if args.output != None:
              arguments.extend(["--output {p}".format(p = args.output)])

          if is_any_windows():
              winsee_clang_path = "C:\\apps\\clang\\bin\\clang.exe"
              arguments.extend(["--use-analyzer {exe}".format(exe = winsee_clang_path )])

          final_command = "{tool} {args}".format(tool = self.tool_name, args = " ".join(arguments))
          result = self.run(final_command)
      else:
          raise EnvironmentError("tool: {tool} not in path, cannot execute.".format(tool = self.tool_name))

      return result

class  Lizard(Tool):
    def execute(self,cdb,args):
        result = 1
        if self.tool_exists():
            temp_name= None
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as t:
                temp_name = t.name
                for compilation_unit in cdb:
                    directory = compilation_unit['directory']
                    filename = compilation_unit['file']
                    absolute_filename = os.path.abspath(os.path.join(directory, filename))
                    if os.path.isfile(absolute_filename) and self.should_scan(absolute_filename, args):
                        t.write("{f}\n".format(f = absolute_filename))

            if os.path.isfile(temp_name):
                arguments = ["-l cpp",
                            "--ignore_warnings -1",
                            "--working_threads {t}".format(t = self.max_tasks(args)),
                            "--input_file {f}".format(f = temp_name),
                            "-ENS"]
                if args.xml == True:
                    arguments.extend(["--xml"])

                tmp_cmd = "lizard {args}".format(args = " ".join(arguments))
                if args.output != None:
                    final_command = "{x} > {y}".format(x = tmp_cmd, y = args.output)
                else:
                    final_command = tmp_cmd
                result = self.run(final_command)
                os.remove(temp_name)
        else:
            raise EnvironmentError("tool: {tool} not in path, cannot execute.".format(tool = self.tool_name))

        return result

class CppCheck(Tool):

    def suppression_file(self):
        return os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "win.supp" if is_any_windows() else "osx.supp"))


    def includes(self,args):
        return filter(lambda arg: '-i' in arg, args[1:-1])

    def execute(self, cdb,args):
        result = 1
        if self.tool_exists():
            all_includes = []
            all_sources = []
            for compilation_unit in cdb:
                directory = compilation_unit['directory']
                temp_name_sources = None
                temp_name_includes = None
                filename = compilation_unit['file']
                absolute_filename = os.path.abspath(os.path.join(directory, filename))
                if os.path.isfile(absolute_filename) and self.should_scan(absolute_filename,args):
                    all_includes.extend(self.includes(compilation_unit['arguments']))
                    all_sources.append(absolute_filename)

            with tempfile.NamedTemporaryFile(mode='w', delete=False) as t:
                try:
                    temp_name_includes = t.name
                    for line in list(set(all_includes)):
                        t.write("{f}\n".format(f = line[:2]))
                    for line in self.system_includes():
                        t.write("{f}\n".format(f = line))
                except:
                  pass

            with tempfile.NamedTemporaryFile(mode='w', delete=False) as t:
                temp_name_sources = t.name
                for line in all_sources:
                    t.write("{f}\n".format(f = line))

            arguments = ["--includes-file={f}".format(f=temp_name_includes),
                         "--file-list={f}".format(f=temp_name_sources),
                         "-j {j}".format(j = self.max_tasks(args)),
                         "--std=c++11",
                         "--library=qt",
                         "--enable=warning,style,performance,portability,unusedFunction,missingInclude",
                         "--inline-suppr",
                         "--force",
                         "--error-exitcode=0"]

            suppressions = self.suppression_file()
            if os.path.isfile(suppressions):
                arguments.append("--suppressions-list={f}".format(f=suppressions))

            cmd = "cppcheck {args}"
            if args.xml == True:
              arguments.extend(["--xml","--xml-version=2"])
            if os.path.isfile(temp_name_includes) and os.path.isfile(temp_name_sources):
                tmp_cmd = cmd.format(args = " ".join(arguments))
                if args.output != None:
                    final_command = "{x} 2> {y}".format(x = tmp_cmd, y = args.output)
                else:
                    final_command = tmp_cmd

                result = self.run(final_command)
                os.remove(temp_name_includes)
                os.remove(temp_name_sources)

        else:
            raise EnvironmentError("tool: {tool} not in path, cannot execute.".format(tool = self.tool_name))
        return result
