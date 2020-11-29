# -*- coding: utf-8 -*-

import os
import re


class Note(object):
    def __init__(self, path, line, column, message):
        self.path = path
        self.line = line
        self.column = column
        self.message = message

    def __eq__(self, other):
        return (
            self.path == other.path and self.line == other.line and self.column == other.column and self.message == other.message
        )

    def __str__(self):
        return "path=%s, line=%d, column=%s, message=%s" % (self.path, self.line, self.column, self.message)


class Message(Note):
    def __init__(self, path, line, column, message, checker, fixits=None, notes=None):
        super(Message, self).__init__(path, line, column, message)
        self.checker = checker
        self.fixits = fixits if fixits else []
        self.notes = notes if notes else []

    def __eq__(self, other):
        return (
            super(Message, self).__eq__(other) and self.checker == other.checker and self.fixits == other.fixits and self.notes == other.notes
        )

    def __str__(self):
        return "%s, checker=%s, fixits=%s, notes=%s" % (
            super(Message, self).__str__(),
            self.checker,
            [str(fixit) for fixit in self.fixits],
            [str(note) for note in self.notes],
        )


class OutputParser(object):
    # Regex for parsing a clang-tidy message.
    message_line_re = re.compile(
        # File path followed by a ':'.
        r"^(?P<path>[\S ]+?):"
        # Line number followed by a ':'.
        r"(?P<line>\d+?):"
        # Column number followed by a ':' and a space.
        r"(?P<column>\d+?): "
        # Severity followed by a ':'.
        r"(?P<severity>(error|warning)):"
        # Checker message.
        r"(?P<message>[\S \t]+)\s*"
        # Checker name.
        r"\[(?P<checker>.*)\]"
    )

    # Matches a note.
    note_line_re = re.compile(
        # File path followed by a ':'.
        r"^(?P<path>[\S ]+?):"
        # Line number followed by a ':'.
        r"(?P<line>\d+?):"
        # Column number followed by a ':' and a space.
        r"(?P<column>\d+?): "
        # Severity == note.
        r"note:"
        # Checker message.
        r"(?P<message>.*)"
    )

    def __init__(self):
        self.messages = []

    def parse_messages_from_file(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            return self.parse_messages(file)

    def parse_messages(self, tidy_out):
        titer = iter(tidy_out)
        try:
            next_line = next(titer)
            while True:
                message, next_line = self._parse_message(titer, next_line)
                if message is not None:
                    self.messages.append(message)
        except StopIteration:
            pass

        return self.messages

    def _parse_message(self, titer, line):
        match = OutputParser.message_line_re.match(line)
        if match is None:
            return None, next(titer)

        message = Message(
            os.path.abspath(match.group("path")),
            int(match.group("line")),
            int(match.group("column")),
            match.group("message").strip(),
            match.group("checker").strip(),
        )

        try:
            line = next(titer)
            line = self._parse_code(message, titer, line)
            line = self._parse_fixits(message, titer, line)
            line = self._parse_notes(message, titer, line)

            return message, line
        except StopIteration:
            return message, ""

    @staticmethod
    def _parse_code(message, titer, line):
        # Eat code line.
        if OutputParser.note_line_re.match(line) or OutputParser.message_line_re.match(line):
            # LOG.debug("Unexpected line: %s. Expected a code line!", line)
            return line

        # Eat arrow line.
        # FIXME: range support?
        line = next(titer)
        if "^" not in line:
            # LOG.debug("Unexpected line: %s. Expected an arrow line!", line)
            return line
        return next(titer)

    @staticmethod
    def _parse_fixits(message, titer, line):
        while OutputParser.message_line_re.match(line) is None and OutputParser.note_line_re.match(line) is None:
            message_text = line.strip()

            if message_text != "":
                message.fixits.append(Note(message.path, message.line, line.find(message_text) + 1, message_text))
            line = next(titer)
        return line

    def _parse_notes(self, message, titer, line):
        while OutputParser.message_line_re.match(line) is None:
            match = OutputParser.note_line_re.match(line)
            if match is None:
                # LOG.debug("Unexpected line: %s", line)
                return next(titer)

            message.notes.append(
                Note(
                    os.path.abspath(match.group("path")),
                    int(match.group("line")),
                    int(match.group("column")),
                    match.group("message").strip(),
                )
            )
            line = next(titer)
            line = self._parse_code(message, titer, line)
        return line
