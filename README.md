processcdb
==========

Simple front-end tool that can run various static analysis tools by
reading the required information from compile_commands.json.

Provides output formatting for integration to other tools, parallerization
when needed, ability to override/reconfigure compiler flags and such on per
"tool" plugin requirements.

Current development is done mainly on Windows but should work on any platform
where you have python, working development environment for your own project
and analyzer. Currently supported ones:

 * clang-tidy
 * cppcheck
 * lizard

Installation
============

Project is available in pypi as source distribution:

    pip install processcdb

Since processcdb will also install few dependencies, using [pipx](https://github.com/pipxproject/pipx) for installation
is adviced.

Once package is installed. Generate a configuration file with:

    processcdb --dump-config

This will generate barebones configuration file to default location (can be overwritten later with
--config argument). Edit this file to point "binary" options for those analyzer to point to their executable.
On windows, do not omit file extension.

Usage
=====

Basic help:

    processcdb --help

After a process of generating a compile_commands.json, you can run processcdb with selected tool like this:

    processcdb --tool clang-tidy

This will try to locate the json file from current working directory and runs the tool, in this case the 
clang-tidy tool as defined in the config file, against all files that are compiled and not blacklisted in processcdb config file or in
tools own configuration file and generates the output to standard output. If you need to run the tool when you
don't have access to change the current working directory, you can pass `--cdb` and absolute location:

    processcdb --tool clang-tidy --cdb D:\src\myproject\build\compile_commands.json

One can direct the tools output to a file with `--output` argument. Worth noting that that certain tools
(`-t`) can provide further arguments for post processing or tool specific purposes:

    processcdb --tool clang-tidy --cdb ~/src/myproject/build/compile_commands.json --output scan.log --xml

If processcdb is invoked without passing `--config` argument, a default configuration file is used. Location
depends on operating system. If you need to analyze multiple projects with different sort of settings or
you want to analyze with different versions of a particular scanner, use multiple configuration files.

For example, if you have a codebase thst you wish to scan with clang 11.0.0 but your project is really compiled
with Microsoft's msvc and you have another project that does compile with clang: make separate config file for
msvc and clang and invoke processcdb:

    processcdb --tool clang-tidy --config location/to/config/msvc17_clang_interop.ini

Configuration
=============

If processcdb is invoked without passing `--config` argument, a default configuration file is used. To generate
a config file, pass `--dump-config` to the processcdb. To save the default config file to a file. either
capture the standard output or provide `--config` parameter.

## Configuration file

Each tool has a separate section and each section can be configured either in the tool specific section or
in default. The minimal single tool configuration would look something like this:

    [clang-tidy]
    binary=C:\llvm-11.0.0\bin\clang-tidy.exe

Here we have section for clang-tidy tool, where we are setting a variable `binary` to a value of
`c:\llvm-11.0.0\bin\clang-tidy.exe`.

Python `configparser` module is used for loading/parsing of the file.

Following variables are shared between the tools:

  * `binary` - absolute path to a scanner.
  * `file_blacklist` - list of file specs that should be omitted from the scan
  * `arg_blacklist` - list of command line arguments passed to compiler that should not be passed to a tool.
  * `arg_additions` - a list of of key/value pairs. If key is found in json, a value is placed into tool's
      arguments.
  * `jobs` - default number processes processcdb or the tool can use to process. 0 for auto detect.
  * `default_includes` - list of paths that should be automatically passed to the tool as include paths which
      might not be be specified in the compile_commands.json
  * `default_args` - list of arguments that should be passed to the tool that are not provided by the
      compile_commands.json
  * `includes_as_system`: list of file specs that that should converted from normal -I include to -isystem
      include.

Each config option that is a list and allows multiple values, use semicolon as item separator.

with `arg_blacklist`, one can strip away unnecessary command line arguments and `arg_addition` can be used to
inject new arguments. For example, if is compiling a project in msvc and exceptions are enabled, following
configuration would allow clang-tidy tool to still work correctly:

```config
[clang-tidy]
binary=C:\llvm-11.0.0\bin\clang-tidy.exe
arg_blacklist=EHsc
arg_additions=EHsc=-Xclang,-fcxx-exceptions
```

As first, processcdb would notice that compile_commands.json might have `/EHsc` argument, it would add 2 new arguments
`-Xclang` and '-fcxx-exceptions' and then arg_blacklist would then remove the original `/EHsc`

cppcheck tool also has option `supression_file` which, if needed, should be absolute location of cppchecks own
suppression file.

Credits
=======

clang-tidy toool's ability to convert the logfile to xml for direct jenkins support is part of [CodeChecker](https://github.com/Ericsson/codechecker) project
and its licensed under Apache 2.0


Links
=====

Home: https://github.com/rasjani/processcdb
Issues: https://github.com/rasjani/processcdb/issues
