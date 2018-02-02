
Simple tool that can be used to scan codebase with various static analysis
tools.

Currently supports:

 * clang-tidy
 * clang static analyzer
 * cppcheck
 * lizard

Notable features:

 * can convert clang-tidy output to xml so that it can be used in jenkins
 * can parallerize clang-tidy execution
 * only scans those files that are part of the build - via using clang's
   compilation database.
 * can provide appropriate flags to cppcheck when  needed

Test on OSX and Windows - but currently probably doesnt run at all as project
is still in early work in progress for public release and many of the features
where written for a very static(!) environment .. Sorry ..


Instructions:

./processcdb.py --help

TODO:
 * Make all the configuration of 3rd party tools to be more user friendly,
   aka, no need to modify code
 * Separate tools as proper plugins that can be added/removed.
 * Documents
 * Provide support for scanning specific commits.
