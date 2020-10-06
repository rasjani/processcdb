import os
import re


class Note(object):
    def __init__(self, path, line, column, severity, message):
        self.path = path
        self.line = line
        self.column = column
        self.severity = severity
        self.message = message

    def __eq__(self, other):
        return (
            self.path == other.path and self.line == other.line and self.column == other.column and self.message == other.message
        )

    def __str__(self):
        return "path=%s, line=%d, column=%s, message=%s" % (self.path, self.line, self.column, self.message)


class Message(Note):
    def __init__(self, path, line, column, severity, message, checker, fixits=None, notes=None, path_miss=False):
        super(Message, self).__init__(path, line, column, severity, message)
        self.checker = checker
        self.fixits = fixits if fixits else []
        self.notes = notes if notes else []
        self.path_miss = path_miss

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
    message_line_re = re.compile(r"^(?P<path>.+): (?P<line>\d+): (?P<column>\d+):\ (?P<severity>\w+): (?P<message>[\S \t]+)\s* \[(?P<checker>.*)\]")

    # Matches a note.
    note_line_re = re.compile(r"^(?P<path>.+): (?P<line>\d+): (?P<column>\d+):\  note: (?P<message>.*)")

    # Matches extra stuff note.
    extra_note_line_re = re.compile(r"^(?P<severity>warning|note):  (?P<message>.*)")

    def __init__(self):
        self.messages = []

    def parse_messages_from_file(self, path):
        with open(path, "r") as file:
            return self.parse_messages(file)

    def parse_messages(self, tidy_out):
        titer = iter(tidy_out)
        try:
            next_line = titer.next()
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
            return None, titer.next()
        path_miss = False
        filepath = os.path.abspath(match.group("path"))
        if not os.path.isfile(filepath):
            path_miss = True
            filepath = match.group("path")

        message = Message(
            filepath,
            int(match.group("line")),
            int(match.group("column")),
            match.group("severity").strip(),
            match.group("message").strip(),
            match.group("checker").strip(),
            path_miss=path_miss,
        )

        try:
            line = titer.next()
            line = self._parse_code(message, titer, line)
            line = self._parse_fixits(message, titer, line)
            line = self._parse_notes(message, titer, line)

            return message, line
        except StopIteration:
            return message, line

    def _parse_code(self, message, titer, line):
        # Eat code line.
        if OutputParser.note_line_re.match(line) or OutputParser.message_line_re.match(line):
            print("Unexpected line: {s}. Expected a code line!".format(s=line))
            return line

        # Eat arrow line.
        # FIXME: range support?
        line = titer.next()
        if "^" not in line:
            print("Unexpected line: {s}. Expected an arrow line!".format(s=line))
            return line
        return titer.next()

    def _parse_fixits(self, message, titer, line):
        while OutputParser.message_line_re.match(line) is None and OutputParser.note_line_re.match(line) is None:

            message_text = line.strip()
            if message_text == "":
                continue

            message.fixits.append(Note(message.path, message.line, line.find(message_text) + 1, "", message_text))
            line = titer.next()
        return line

    def _parse_notes(self, message, titer, line):
        while OutputParser.message_line_re.match(line) is None:
            match = OutputParser.note_line_re.match(line) or OutputParser.extra_note_line_re.match(line)
            if match is None:
                print("Unexpected line: {s}".format(s=line))
                return titer.next()

            if "severity" in match.groupdict().keys():
                message.notes.append(
                    Note(
                        os.path.abspath(message.path),
                        int(message.line),
                        int(message.column),
                        "",
                        match.group("message").strip(),
                    )
                )
            else:
                if message.path_miss:
                    directory = os.path.dirname(match.group("path"))
                    new_message_path = os.path.abspath(os.path.join(directory, message.path))
                    if os.path.isfile(new_message_path):
                        message.path_miss = False
                        message.path = new_message_path

                message.notes.append(
                    Note(
                        os.path.abspath(match.group("path")),
                        int(match.group("line")),
                        int(match.group("column")),
                        "",
                        match.group("message").strip(),
                    )
                )

            line = titer.next()
            if "severity" not in match.groupdict().keys():
                line = self._parse_code(message, titer, line)

        return line
