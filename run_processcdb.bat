@echo off
pushd

D:\fone\branch\external\ego\dev\python3\bin\python.exe src/processcdb --tool clang-tidy --xml --output results.xml --cdb D:\fone\branch\external\ego\dev\clang_tools\compile_commands.json

popd