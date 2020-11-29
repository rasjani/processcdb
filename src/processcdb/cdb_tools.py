# -*- coding: utf-8 -*-

from .toolbase import Tool  # noqa: F401
from .clangtidy import ClangTidy  # noqa: F401
from .clang import Clang  # noqa: F401
from .lizard import Lizard  # noqa: F401
from .cppcheck import CppCheck  # noqa: F401

TOOLS = {
    "clang-tidy": ClangTidy,
    "lizard": Lizard,
    "cppcheck": CppCheck,
    # "clang": Clang,  DISABLE FOR NOW. Not working
}
__all__ = ["Tool", "ClangTidy", "Lizard", "CppCheck", "TOOLS"]
