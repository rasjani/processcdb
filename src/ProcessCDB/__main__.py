import argparse
import os
import json
from .cdb_tools import ClangTidy, CppCheck, Lizard, Clang, remove_untouched_files, remove_dupes

tools = {
    "clang-tidy": ClangTidy("clang-tidy"),
    "lizard": Lizard("lizard"),
    "cppcheck": CppCheck("cppcheck"),
    "clang": Clang("analyze-build"),
}

parser = argparse.ArgumentParser(
    description="Static analysis wrapper", epilog="Available tools: \n{}".format(",".join(tools.keys()))
)
parser.add_argument(
    "--cdb",
    "-c",
    action="store",
    dest="cdb",
    metavar="f",
    default="compile_commands.json",
    help="Full name with path to compile_commands.json one wishes to process",
)
parser.add_argument(
    "--tool",
    "-t",
    action="store",
    dest="tool",
    default="clang-tidy",
    metavar="toolname",
    help="Tool to use to process cdb file",
)
xml = parser.add_mutually_exclusive_group()
xml.add_argument(
    "--xml", dest="xml", action="store_true", help="If the tool allows, generate report in XML, defaults to plaintext"
)
xml.add_argument("--no-xml", dest="xml", action="store_false")
parser.set_defaults(xml=False)

allow_dupes = parser.add_mutually_exclusive_group()
allow_dupes.add_argument(
    "--dupes",
    dest="allow_dupes",
    action="store_true",
    help="Allow duplicates in cdb to be scanned. Defaults to no-dupes",
)
allow_dupes.add_argument("--no-dupes", dest="allow_dupes", action="store_false")
parser.set_defaults(allow_dupes=False)


parser.set_defaults(xml=False)
parser.add_argument(
    "--output",
    "-o",
    action="store",
    dest="output",
    default=None,
    metavar="f",
    help="Where results will be stored. Depending on the tool, this is either directory or a explicit file",
)
parser.add_argument(
    "--jobs",
    "-j",
    type=int,
    dest="jobs",
    action="store",
    default=0,
    metavar="N",
    help="If chosen tool allows, use this many parallel processes. 0 for automatic detection, otherwise, limit to N",
)
parser.add_argument(
    "--commit-a",
    type=str,
    dest="commit_a",
    action="store",
    default=None,
    metavar="N",
    help="Limit scanning to particular commit^",
)
parser.add_argument(
    "--commit-b",
    type=str,
    dest="commit_b",
    action="store",
    default=None,
    metavar="N",
    help="If specified, scan between commit-a and commit-b, otherwise commit-a is commit-a^",
)
parser.add_argument(
    "file",
    nargs="*",
    type=os.path.abspath,
    help="If specified, scan only these files if they are found in cdb. If files specified here are not absolute paths, they will be relative the working directory",
)
args = parser.parse_args()
cdb = None

if os.path.isfile(args.cdb):
    with open(args.cdb) as data_file:
        cdb = json.load(data_file)
    if cdb is not None:
        if args.commit_a is not None:
            cdb = remove_untouched_files(cdb, (args.commit_a, args.commit_b))
        if not args.allow_dupes:
            cdb = remove_dupes(cdb)
        if args.tool in tools.keys():
            tool = tools[args.tool]
            try:
                ret = tool.execute(cdb, args)
                print("Info: Return value from tool process: {}".format(str(ret)))
            except EnvironmentError as e:
                print("Error: Cant process: {}".format(str(e)))
            except Exception as e:
                print("Error: {}".format(str(e)))
        else:
            print("Error: Unknown tool {} - cant initilize".format(args.tool))
    else:
        print("Error: File '{}' is empty".format(args.cdb))
else:
    print("Error: File '{}' does not exist".format(args.cdb))
