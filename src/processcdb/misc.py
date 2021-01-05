# -*- coding: utf-8 -*-

import platform
import subprocess
from pathlib import Path
from collections import ChainMap
import argparse
from _version import get_versions
from logger import LOGGER as log, LOG_LEVELS  # noqa: F401

def is_windows():
    return "WINDOWS" in platform.system().upper()


def is_cygwin():
    return "CYGWIN" in platform.system().upper()


def is_any_windows():
    return is_windows() or is_cygwin()


def is_mac():
    return "Darwin" in platform.system()


def capture_output(args, captureErr=True, capture_exceptions=True):
    buff = ""
    params = {"shell": True, "universal_newlines": True}
    if captureErr:
        params["stderr"] = subprocess.STDOUT
    try:
        buff = subprocess.check_output(args, **params)
    except subprocess.CalledProcessError as e:
        buff = e.stdout
        if capture_exceptions:
            with open("error.log", "a") as f:
                f.write(f"ARGUMENTS: {args}\n")
                f.write(f"STDOUT: {e.stdout}\n")
                f.write("---------------------------------------\n")
    return buff.split("\n")


def remove_dupes(cdb):
    seen = []
    new_cdb = []
    for entry in cdb:
        current = Path(entry["directory"]) / entry["file"]
        if current not in seen:
            new_cdb.append(entry)
            seen.append(current)
    return new_cdb


def argument_parser(tools):
    # TODO: Offload tool specific argument to the tool class itself if possible.
    default_config_file = "processcdb.ini"
    parser = argparse.ArgumentParser(description="Static analysis wrapper", epilog=f"Available tools: \n{','.join(tools.keys())}")
    parser.add_argument(
        "--cdb",
        "-c",
        action="store",
        dest="cdb",
        metavar="f",
        type=Path,
        default=Path("compile_commands.json"),
        help="Full name with path to compile_commands.json one wishes to process",
    )
    parser.add_argument(
        "--tool",
        "-t",
        action="store",
        dest="tool",
        default="clang-tidy",
        metavar="toolname",
        type=str,
        help="Tool to use to process cdb file",
    )
    parser.add_argument(
        "--config",
        action="store",
        dest="config",
        metavar="f",
        default=default_config_file,
        type=Path,
        help=f"Absolute path to a file where default configurations are loaded from. Default: {default_config_file}",
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
        type=Path,
        help="If specified, scan only these files if they are found in cdb. If files specified here are not absolute paths, they will be relative the working directory",
    )
    parser.add_argument(
        "--dump-configs",
        dest="dumpconfigs",
        default=False,
        action="store_true",
        help="Generates default configuration",
    )
    parser.add_argument(
        "-l", "--loglevel", default="info", dest="loglevel", choices=list(LOG_LEVELS.keys())[1:], help="Log Level"
    )
    return parser


def to_list(value):
    return value.split(";")


def to_dict(value):
    if value == None or value == '':
        return None
    
    def format(val):
        k,v = val.split("=", 2)
        return {k: v.split(",")}
    return dict(ChainMap(*map(format, to_list(value))))
