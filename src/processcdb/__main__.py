# -*- coding: utf-8 -*-

import sys
import json
import traceback
from .cdb_tools import TOOLS
from .misc import remove_untouched_files, remove_dupes, argument_parser
from configparser import ConfigParser
from .logger import LOGGER as log, LOG_LEVELS


def main():
    args = argument_parser(TOOLS).parse_args()
    log.setLevel(LOG_LEVELS[args.loglevel])
    cdb = None
    ret = 0
    processcdb_config = ConfigParser()

    if args.dumpconfigs:
        for tool_name in TOOLS:
            tool = TOOLS[tool_name](tool_name)
            processcdb_config[tool_name] = tool.default_config()
        config_file = args.config.absolute()
        config_file.parent.mkdir(parents=True, exist_ok=True)
        if config_file.exists():
            log.warn(f"Configuration file {config_file} already exists, overwriting")
        with config_file.open("w") as output:
            processcdb_config.write(output)
        log.info(f"Configuration file written to {config_file}")
        sys.exit(0)

    processcdb_config.read(args.config)
    try:
        tool = TOOLS[args.tool](args.tool, processcdb_config)
    except KeyError:
        log.error(f"Unknown tool '{args.tool}' - cant initilize")
        return 127

    if args.cdb.is_file():
        cdb = json.loads(args.cdb.read_text())
        if cdb:
            if args.commit_a is not None:
                cdb = remove_untouched_files(cdb, (args.commit_a, args.commit_b))

            if not args.allow_dupes:
                cdb = remove_dupes(cdb)

            try:
                ret = tool.execute(cdb, args)
                log.info(f"Return value from tool process: {ret}")
            except EnvironmentError as e:
                log.error(f"Cant process: {e}")
            except Exception as e:
                log.error(f"{e}")
                traceback.print_exc()
        else:
            log.error(f"File '{args.cdb}' is empty")
    else:
        log.error(f"File '{args.cdb}' does not exist")
    return ret  # TODO: Add proper return codes


if __name__ == "__main__":
    sys.exit(main())
