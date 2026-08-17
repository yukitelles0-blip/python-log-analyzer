# Log Analyzer — Blue Team

## 📌 Descrição

Este é o meu primeiro projeto de Cybersecurity: uma ferramenta em Python que analisa arquivos de log de autenticação e identifica padrões potencialmente suspeitos, como possíveis tentativas de força bruta.

O projeto foi criado com fins **educacionais**, como parte dos meus estudos em Python, Redes e Segurança da Informação, com foco em Blue Team / SOC.

> ⚠️ Este projeto funciona apenas com logs locais ou fictícios, criados para fins de laboratório. Ele **não** ataca, escaneia ou interage com sistemas reais.

## 🎯 Objetivo

Praticar conceitos fundamentais de análise de logs, que é uma das tarefas mais comuns do dia a dia de um analista de SOC (Security Operations Center):

- ler e interpretar arquivos de log;
- identificar tentativas de login malsucedidas;
- detectar padrões que possam indicar força bruta;
- gerar um relatório resumido dos eventos.

## 🛠️ Tecnologias utilizadas

- Python 3
- Módulo `re` (expressões regulares) da biblioteca padrão
- `pytest` para os testes automatizados

Nenhuma biblioteca externa de rede ou automação foi usada — apenas o necessário para leitura e análise de texto.

## ✅ Funcionalidades

- [x] Leitura de arquivo de log informado pelo usuário
- [x] Identificação de logins malsucedidos (`LOGIN_FAILED`)
- [x] Identificação de logins bem-sucedidos (`LOGIN_SUCCESS`)
- [x] Contagem de falhas de login por endereço IP
- [x] Detecção de possíveis tentativas de força bruta (5+ falhas do mesmo IP)
- [x] Geração de alertas para IPs suspeitos
- [x] Resumo final da análise (total de eventos, IPs analisados, IPs suspeitos)
- [x] Tratamento de erros (arquivo inexistente, formato inválido)
- [x] Testes automatizados com `pytest`

## 📁 Estrutura do projeto

```
log-analyzer/
│
├── README.md
├── requirements.txt
├── .gitignore
├── sample.log
│
├── src/
│   ├── main.py          # Ponto de entrada do programa
│   ├── log_parser.py    # Leitura e interpretação do arquivo de log
│   ├── analyzer.py      # Lógica de análise (contagens, detecção)
│   └── reporter.py      # Exibição dos resultados no terminal
│
└── tests/
    └── test_analyzer.py # Testes automatizados com pytest
```

Cada módulo tem uma única responsabilidade, o que deixa o código mais fácil de entender, testar e evoluir — foi uma das primeiras boas práticas de Python que apliquei de verdade neste projeto.

## 💻 Como instalar

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/log-analyzer.git
   cd log-analyzer
   ```

2. (Opcional, mas recomendado) Crie um ambiente virtual:
   ```bash
   python -m venv venv
   venv\Scripts\activate      # Windows
   source venv/bin/activate   # Linux/Mac
   ```

3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

## ▶️ Como executar

A partir da pasta raiz do projeto (`log-analyzer/`), execute:

```bash
python src/main.py
```

O programa vai pedir o caminho do arquivo de log. Para testar com o log de exemplo, digite:

```
sample.log
```

## 🧪 Como executar os testes

A partir da pasta raiz do projeto:

```bash
pytest tests/
```

Os testes cobrem:
- leitura do arquivo de log;
- identificação de `LOGIN_FAILED` e `LOGIN_SUCCESS`;
- contagem de falhas por IP;
- geração de alerta ao atingir o limite configurado;
- tratamento de erro para arquivo inexistente.

## 📤 Exemplo de saída

```
========================================
LOG ANALYZER - BLUE TEAM
========================================

[+] Arquivo analisado: sample.log

[+] Eventos analisados: 20

[+] Login bem-sucedido: 9
[!] Login malsucedido: 11

----------------------------------------
      ALERTAS
----------------------------------------

[!] Possível atividade suspeita
IP: 192.168.1.10
Tentativas: 7

----------------------------------------
      RESUMO
----------------------------------------

IPs analisados: 12
IPs suspeitos: 1

========================================
```

## 📚 O que aprendi desenvolvendo este projeto

- Como usar expressões regulares (`re`) para extrair informações estruturadas de texto bruto.
- Como separar um programa em módulos com responsabilidades bem definidas (parser, analyzer, reporter).
- Como tratar erros comuns em Python (`try/except`) de forma que o programa nunca "quebre feio" para o usuário.
- Como escrever testes automatizados básicos com `pytest`, incluindo o uso de fixtures como `tmp_path`.
- Uma introdução prática a como um analista de Blue Team pensa ao olhar para um log: não é só "achar erro", é procurar **padrões** que indiquem risco.

## 🚀 Possíveis melhorias futuras

- Suportar outros formatos de log (JSON, CSV, logs de firewall reais).
- Adicionar detecção de outros padrões suspeitos (ex: horários incomuns, múltiplos usuários testados no mesmo IP).
- Exportar o relatório para um arquivo (`.txt`, `.csv` ou `.json`).
- Permitir configurar o limite de força bruta via linha de comando (`argparse`).
- Adicionar cores no terminal para destacar alertas.
- Criar uma versão simples com interface web (Flask) para visualizar os resultados.

## ⚠️ Aviso de uso educacional

Este projeto foi desenvolvido **exclusivamente para fins de estudo**. Ele não deve ser usado para monitorar, analisar ou interagir com sistemas ou logs de terceiros sem autorização explícita. Os dados presentes em `sample.log` são fictícios.
