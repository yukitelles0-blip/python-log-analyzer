
"""
analyzer.py

Responsável por analisar eventos de autenticação,
identificar comportamentos suspeitos e gerar estatísticas.
"""

from collections import defaultdict
from datetime import timedelta


# Configurações de detecção
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


def count_failed_logins_by_ip(events):
    """Conta as tentativas malsucedidas por endereço IP."""
    failed_counts = {}

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            ip = event["ip"]
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    return failed_counts


def get_successful_logins(events):
    """Retorna os eventos de login bem-sucedido."""
    return [
        event for event in events
        if event["event_type"] == "LOGIN_SUCCESS"
    ]


def get_failed_logins(events):
    """Retorna os eventos de login malsucedido."""
    return [
        event for event in events
        if event["event_type"] == "LOGIN_FAILED"
    ]


def detect_suspicious_ips(
    failed_counts,
    threshold=BRUTE_FORCE_THRESHOLD
):
    """
    Identifica IPs que atingiram o limite total de falhas.

    Esta regra considera a quantidade total de falhas,
    independentemente do intervalo de tempo.
    """
    suspicious = []

    for ip, attempts in failed_counts.items():
        if attempts >= threshold:
            suspicious.append({
                "ip": ip,
                "attempts": attempts
            })

    return suspicious


def detect_brute_force_by_time(
    events,
    threshold=BRUTE_FORCE_THRESHOLD,
    window_seconds=TIME_WINDOW_SECONDS
):
    """
    Identifica IPs com várias falhas dentro de uma janela temporal.

    Retorna o maior conjunto de tentativas encontrado por IP
    dentro do intervalo configurado.
    """

    failed_by_ip = defaultdict(list)

    # Separa as falhas por endereço IP.
    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            failed_by_ip[event["ip"]].append(event)

    alerts = []

    for ip, ip_events in failed_by_ip.items():

        # Garante que os eventos estejam em ordem cronológica.
        ip_events.sort(key=lambda event: event["timestamp"])

        left = 0
        best_window = []

        for right in range(len(ip_events)):

            # Remove eventos que ficaram fora da janela.
            while (
                ip_events[right]["timestamp"]
                - ip_events[left]["timestamp"]
            ).total_seconds() > window_seconds:
                left += 1

            current_count = right - left + 1

            if current_count > len(best_window):
                best_window = ip_events[left:right + 1]

        if len(best_window) >= threshold:
            alerts.append({
                "ip": ip,
                "attempts": len(best_window),
                "window_start": best_window[0]["timestamp"],
                "window_end": best_window[-1]["timestamp"],
                "users": sorted({
                    event["user"] for event in best_window
                })
            })

    return alerts


def get_suspicious_users(events):
    """Conta quantas falhas de autenticação cada usuário recebeu."""
    failed_users = {}

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            user = event["user"]
            failed_users[user] = failed_users.get(user, 0) + 1

    return sorted(
        [
            {"user": user, "attempts": attempts}
            for user, attempts in failed_users.items()
        ],
        key=lambda item: item["attempts"],
        reverse=True
    )


def build_summary(events, suspicious_ips):
    """Gera as estatísticas gerais da análise."""

    total_events = len(events)
    total_success = len(get_successful_logins(events))
    total_failed = len(get_failed_logins(events))
    total_ips_analisados = len({
        event["ip"] for event in events
    })

    return {
        "total_events": total_events,
        "total_success": total_success,
        "total_failed": total_failed,
        "total_ips_analisados": total_ips_analisados,
        "total_ips_suspeitos": len(suspicious_ips)
    }
