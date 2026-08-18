# Log Analyzer — Blue Team

## 📌 Descrição

Este é o meu primeiro projeto de Cybersecurity: uma ferramenta em Python que analisa arquivos de log de autenticação e identifica padrões potencialmente suspeitos, como possíveis tentativas de força bruta.

O projeto foi criado com fins **educacionais**, como parte dos meus estudos em Python, Redes e Segurança da Informação, com foco em Blue Team / SOC.

> ⚠️ Este projeto funciona apenas com logs locais ou fictícios, criados para fins de laboratório. Ele **não ataca, escaneia ou interage com sistemas reais**.

## 🎯 Objetivo

Praticar conceitos fundamentais de análise de logs, comuns no trabalho de um analista de SOC (Security Operations Center):

- ler e interpretar arquivos de log;
- identificar tentativas de login malsucedidas;
- detectar padrões que possam indicar força bruta;
- validar endereços IP;
- gerar um relatório resumido dos eventos;
- praticar testes automatizados em Python.

## 🛠️ Tecnologias utilizadas

- Python 3
- `re` — expressões regulares
- `ipaddress` — validação de endereços IP
- `pytest` — testes automatizados

Os módulos `re` e `ipaddress` fazem parte da biblioteca padrão do Python.

## ✅ Funcionalidades

- [x] Leitura de arquivo de log informado pelo usuário
- [x] Identificação de logins malsucedidos (`LOGIN_FAILED`)
- [x] Identificação de logins bem-sucedidos (`LOGIN_SUCCESS`)
- [x] Contagem de falhas de login por endereço IP
- [x] Validação de endereços IP
- [x] Detecção de possíveis tentativas de força bruta (5+ falhas do mesmo IP)
- [x] Geração de alertas para IPs suspeitos
- [x] Resumo final da análise
- [x] Tratamento de erros
- [x] Testes automatizados com `pytest`

## 📁 Estrutura do projeto

```text
log-analyzer/
│
├── README.md
├── requirements.txt
├── .gitignore
├── sample.log
│
├── main.py
├── log_parser.py
├── analyzer.py
├── reporter.py
└── test_analyzer.py
