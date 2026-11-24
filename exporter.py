
import csv
import json
from datetime import date, datetime
from pathlib import Path


def make_json_serializable(data):
    """Converte datas e estruturas aninhadas para formatos compatíveis com JSON."""

    if isinstance(data, (datetime, date)):
        return data.isoformat()

    if isinstance(data, dict):
        return {
            str(key): make_json_serializable(value)
            for key, value in data.items()
        }

    if isinstance(data, (list, tuple)):
        return [make_json_serializable(item) for item in data]

    return data


def build_report(
    file_path,
    summary,
    suspicious_ips,
    temporal_alerts,
    suspicious_users
):
    """Organiza os resultados da análise em uma estrutura única."""

    return {
        "arquivo_analisado": str(file_path),
        "data_geracao": datetime.now().astimezone().isoformat(),
        "resumo": summary,
        "alertas_historicos": suspicious_ips,
        "alertas_temporais": temporal_alerts,
        "usuarios_suspeitos": suspicious_users
    }


def export_json(report, output_dir="reports"):
    """Exporta o relatório completo em formato JSON."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = output_path / "security_report.json"

    safe_report = make_json_serializable(report)

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(
            safe_report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return file_path


def export_csv(report, output_dir="reports"):
    """Exporta os resultados em formato CSV."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = output_path / "security_report.csv"

    sections = [
        "resumo",
        "alertas_historicos",
        "alertas_temporais",
        "usuarios_suspeitos"
    ]

    with file_path.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.writer(file, delimiter=";")

        writer.writerow(["categoria", "detalhes"])

        for section in sections:
            content = report.get(section, [])

            if isinstance(content, list):
                for item in content:
                    writer.writerow([
                        section,
                        json.dumps(
                            make_json_serializable(item),
                            ensure_ascii=False
                        )
                    ])

            else:
                writer.writerow([
                    section,
                    json.dumps(
                        make_json_serializable(content),
                        ensure_ascii=False
                    )
                ])

    return file_path


def export_reports(
    file_path,
    summary,
    suspicious_ips,
    temporal_alerts,
    suspicious_users,
    output_dir="reports"
):
    """Gera os relatórios JSON e CSV."""

    report = build_report(
        file_path,
        summary,
        suspicious_ips,
        temporal_alerts,
        suspicious_users
    )

    json_file = export_json(report, output_dir)
    csv_file = export_csv(report, output_dir)

    return json_file, csv_file
