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

Support for clang static analyzer might be re-enabled later.

New scanners can be added later.
