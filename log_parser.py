
"""
log_parser.py

Responsável por ler arquivos de log e transformar cada linha
em um evento estruturado.
"""

import re
import ipaddress
from datetime import datetime


LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'IP=(?P<ip>\S+)\s+'
    r'(?P<event_type>LOGIN_FAILED|LOGIN_SUCCESS)\s+'
    r'user=(?P<user>\S+)$'
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def read_log_file(file_path):
    """Lê o arquivo e retorna suas linhas."""
    with open(file_path, "r", encoding="utf-8") as file:
        return file.readlines()


def parse_line(line):
    """Converte uma linha válida em um evento estruturado."""
    line = line.strip()

    if not line:
        return None

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    event = match.groupdict()

    try:
        event["timestamp"] = datetime.strptime(
            event["timestamp"], DATE_FORMAT
        )

        ipaddress.ip_address(event["ip"])

    except ValueError:
        return None

    return event


def parse_log_file(file_path):
    """Retorna os eventos válidos e contabiliza linhas inválidas."""
    lines = read_log_file(file_path)

    events = []
    invalid_lines = 0

    for line in lines:
        event = parse_line(line)

        if event is not None:
            events.append(event)
        elif line.strip():
            invalid_lines += 1

    return events, invalid_lines
