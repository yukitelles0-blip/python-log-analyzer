"""
log_parser.py

Responsavel por ler o arquivo de log e transformar cada linha
em um "evento" estruturado (dicionario), que os outros modulos
podem usar facilmente.
"""

import re
import ipaddress


# Padrao esperado de cada linha do log:
# 2026-08-17 08:30:01 IP=192.168.1.10 LOGIN_FAILED user=admin
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'IP=(?P<ip>\S+)\s+'
    r'(?P<event_type>LOGIN_FAILED|LOGIN_SUCCESS)\s+'
    r'user=(?P<user>\S+)$'
)


def read_log_file(file_path):
    """
    Le o arquivo de log e retorna uma lista de linhas (strings).
    """
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    return lines


def parse_line(line):
    """
    Transforma uma linha de log em um dicionario de evento.

    Retorna None se a linha nao seguir o formato esperado
    ou se o IP nao for valido.
    """
    line = line.strip()

    if not line:
        return None

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    event = match.groupdict()

    try:
        ipaddress.ip_address(event["ip"])
    except ValueError:
        return None

    return event


def parse_log_file(file_path):
    """
    Le o arquivo de log e retorna uma lista de eventos validos.
    """
    lines = read_log_file(file_path)

    events = []

    for line in lines:
        event = parse_line(line)

        if event is not None:
            events.append(event)

    return events
