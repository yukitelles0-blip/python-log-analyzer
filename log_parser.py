"""
log_parser.py

Responsavel por ler o arquivo de log e transformar cada linha
em um "evento" estruturado (dicionario), que os outros modulos
podem usar facilmente.
"""

import re

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

    Levanta FileNotFoundError se o arquivo nao existir
    (o Python ja faz isso sozinho com open(), entao nem
    precisamos tratar aqui dentro).
    """
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return lines


def parse_line(line):
    """
    Tenta transformar uma linha de log em um dicionario de evento.

    Retorna um dicionario no formato:
    {
        "timestamp": "2026-08-17 08:30:01",
        "ip": "192.168.1.10",
        "event_type": "LOGIN_FAILED",
        "user": "admin"
    }

    Retorna None se a linha nao seguir o formato esperado.
    Assim, uma linha "quebrada" no meio do arquivo nao derruba
    o programa inteiro, ela e simplesmente ignorada.
    """
    line = line.strip()

    if not line:
        return None

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    return match.groupdict()


def parse_log_file(file_path):
    """
    Le o arquivo de log e retorna uma lista de eventos validos (dicionarios).

    Linhas que nao seguem o formato esperado sao ignoradas.
    """
    lines = read_log_file(file_path)

    events = []
    for line in lines:
        event = parse_line(line)
        if event is not None:
            events.append(event)

    return events
