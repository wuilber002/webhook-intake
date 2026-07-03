# Webhook Intake

[![Tests](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml/badge.svg)](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Certbot 5.4+](https://img.shields.io/badge/Certbot-5.4%2B-003A70)](https://certbot.eff.org/)

Read this document in [English](README.md).

Servidor HTTP leve para receber mensagens via webhook e gravá-las localmente. Ele não valida a origem criptograficamente; use-o atrás de uma rede ou proxy confiável (ou adicione autenticação no proxy) antes de expô-lo à internet.

## Aviso legal

Este material é disponibilizado no estado em que se encontra, sem garantias expressas ou implícitas, incluindo garantias de adequação a uma finalidade específica, disponibilidade, segurança, continuidade ou compatibilidade.

Não há compromisso de suporte, acordo de nível de serviço, manutenção ou evolução. O uso, modificação e redistribuição são de inteira responsabilidade e por conta e risco do usuário.

Antes de qualquer utilização, cabe ao usuário validar o comportamento, a segurança, a conformidade e a adequação operacional ao seu ambiente. Os autores e colaboradores não se responsabilizam por perdas, danos, interrupções de serviço, configurações incorretas ou impactos não intencionais decorrentes do uso deste material.

## Requisitos e início

Python 3.11 ou superior. Não há dependências externas de Python. OpenSSL é necessário somente para gerar certificado TLS autoassinado. Crie uma configuração local antes de iniciar:

```bash
cp config.ini.example config.ini
python3 webhook.py --config config.ini
```

O endpoint é `POST /webhook` e a checagem é `GET /healthz`. O arquivo [config.ini.example](config.ini.example) fornecido escuta somente em `127.0.0.1:1604` e grava em `./output/`. Copie-o para `config.ini` e exponha outro endereço somente atrás de firewall ou proxy reverso confiável.

### Quadro de requisitos

| Cenário | Componentes necessários | Rede e privilégios |
| --- | --- | --- |
| Webhook HTTP ou certificado TLS existente | Python 3.11+ | Libere a porta configurada do webhook somente quando emissores externos precisarem dela. |
| HTTPS autoassinado | Python 3.11+, OpenSSL | Não exige porta pública adicional; os clientes precisam confiar explicitamente no certificado. |
| Certificado de IP público com `--certbot-mode` | Python 3.11+, Certbot 5.4+ | IP público estático, TCP/80 de entrada durante a validação e permissão para abrir essa porta, normalmente root. |
| Renovação automática do certificado IP | Timer/hook de renovação do Certbot | Reinicie o webhook após a renovação para recarregar o certificado. |
| HTTP Basic Auth | Variável de ambiente com a senha configurada | Use HTTPS quando exposto fora do loopback, ou proxy TLS confiável com bind em loopback. |
| Serviço systemd | systemd, Python 3.11+ com suporte a `venv` | Acesso root é necessário somente para instalar e administrar o serviço. |

`certbot` e `openssl` são ferramentas do sistema operacional, não pacotes Python instalados no ambiente virtual deste projeto. O script não instala nenhuma delas automaticamente.

### Pré-requisitos de conectividade de rede

Antes de expor o receptor para emissores externos, confirme que cada caminho necessário está liberado tanto no firewall do sistema operacional quanto no firewall, grupo de segurança ou regra de rede do provedor/cloud:

| Fluxo | Protocolo e porta | Quando é necessário |
| --- | --- | --- |
| Emissor → host do webhook | TCP/1604 por padrão, ou a `port` configurada | Necessário para entrega externa de webhook. Restrinja os IPs de origem sempre que possível. |
| Autoridade certificadora → host do webhook | TCP/80 | Necessário somente enquanto o Certbot standalone valida um certificado de IP público. |
| Host do webhook → autoridade certificadora | TCP/443 de saída | Necessário para solicitação e renovação do certificado pelo Certbot. |

Em sistemas com firewalld, libere a porta do webhook com `firewall-cmd --permanent --add-port=1604/tcp` e depois `firewall-cmd --reload`. Abrir somente o firewall do host não é suficiente se um firewall, roteador, balanceador ou grupo de segurança do cloud ainda bloquear o caminho.

Para ver cada entrega no terminal (inclusive o perfil encontrado), use:

```bash
python3 webhook.py --config config.ini --debug
```

Também é possível sobrescrever host e porta: `--host 0.0.0.0 --port 1604`.

## Execução como serviço systemd

Para um host de execução contínua, use os [arquivos de implantação com systemd](systemd/) fornecidos, em vez de um modo daemon no Python. O `systemd` mantém o processo em primeiro plano, registra a saída no journal, reinicia-o após falha inesperada e aplica uma conta de serviço e acesso restrito ao sistema de arquivos.

O instalador usa esta estrutura por padrão:

| Finalidade | Local padrão |
| --- | --- |
| Checkout da aplicação e ambiente virtual | `/opt/webhook-intake` |
| Configuração, perfis e material TLS | `/etc/webhook-intake` |
| Saídas recebidas | `/var/lib/webhook-intake/output` |
| Conta do serviço | `whintake` |

Instale o checkout em `/opt/webhook-intake` e execute o instalador como root. Ele cria a conta de serviço e o ambiente virtual, copia a configuração inicial e os perfis `.conf` fornecidos somente quando ainda não existem, instala as units e recarrega o systemd. Ele não inicia o receptor nem sobrescreve configuração existente.

```bash
sudo git clone https://github.com/wuilber002/webhook-intake.git /opt/webhook-intake
cd /opt/webhook-intake
sudo bash ./systemd/install.sh
sudoedit /etc/webhook-intake/config.ini
sudo systemctl enable --now webhook-intake.service
```

Use `systemctl status webhook-intake.service` para consultar o estado e `journalctl -u webhook-intake.service -f` para acompanhar os logs. Defina `debug = true` em `/etc/webhook-intake/config.ini` quando precisar temporariamente de diagnóstico de entregas; a saída de depuração fica registrada no journal.

A unit do serviço permite escrita intencionalmente apenas em `/var/lib/webhook-intake`. Provisione os arquivos TLS antes de iniciá-la: coloque certificado e chave privada existentes em `/etc/webhook-intake/tls/`, de propriedade de `whintake`, com a chave privada no modo `0600`. Para um certificado autoassinado, habilite TLS e `tls_self_signed = true`, execute uma vez o comando abaixo, interrompa-o com `Ctrl+C` depois que o certificado for criado, defina `tls_self_signed = false` e então inicie o serviço:

```bash
sudo -u whintake /opt/webhook-intake/.venv/bin/python \
  /opt/webhook-intake/webhook.py --config /etc/webhook-intake/config.ini
```

Para Basic Auth em uma instalação systemd, crie o hash da senha como a conta de serviço e defina `basic_auth_enabled = true` em `/etc/webhook-intake/config.ini`:

```bash
sudo -u whintake /opt/webhook-intake/.venv/bin/python \
  /opt/webhook-intake/webhook.py \
  --create-basic-auth-password-file /etc/webhook-intake/.faj383hfa
sudo systemctl restart webhook-intake.service
```

O modelo de configuração do systemd já aponta `basic_auth_password_file` para esse arquivo. Assim, a senha não precisa ficar na unit do systemd nem no ambiente do processo.

### Renovação do Certbot com systemd

Depois de solicitar com sucesso um certificado de IP, habilite o timer fornecido. Ele executa o Certbot diariamente com atraso aleatório. Quando houver renovação, o hook de deploy copia os novos arquivos para `/etc/webhook-intake/tls/` com propriedade da conta de serviço e reinicia o receptor. Confirme que o executável do `certbot` é `/usr/bin/certbot`, ou altere [a unit de renovação](systemd/webhook-intake-certbot-renew.service) antes da instalação.

```bash
sudo /opt/webhook-intake/.venv/bin/python /opt/webhook-intake/webhook.py \
  --config /etc/webhook-intake/config.ini --certbot-mode \
  --certbot-ip 198.51.100.10 --certbot-email admin@example.com
sudo systemctl enable --now webhook-intake-certbot-renew.timer
systemctl list-timers webhook-intake-certbot-renew.timer
```

O Certbot standalone precisa temporariamente de TCP/80. Portanto, pare outro processo que use essa porta e mantenha-a alcançável durante a validação. Inicie ou reinicie `webhook-intake.service` após emitir o primeiro certificado.

## HTTPS

HTTPS direto é opcional. Ative-o no `config.ini` local e informe um certificado e uma chave existentes:

```ini
tls_enabled = true
tls_cert_file = /etc/webhook-intake/fullchain.pem
tls_key_file = /etc/webhook-intake/privkey.pem
```

O servidor passa a escutar em `https://host:port/webhook` e exige TLS 1.2 ou superior. Mantenha os caminhos das chaves privadas fora do repositório.

Para desenvolvimento ou ambiente interno controlado, o script pode criar o próprio certificado na primeira inicialização:

```ini
tls_enabled = true
tls_self_signed = true
tls_cert_file = ./tls/webhook-intake.crt
tls_key_file = ./tls/webhook-intake.key
tls_self_signed_common_name = localhost
tls_self_signed_days = 365
```

Certificados autoassinados exigem [OpenSSL](https://www.openssl.org/) e não são confiados por clientes por padrão. Para um teste local, use `curl -k https://127.0.0.1:1604/webhook ...`; não use `-k` em produção. Para serviços públicos, use certificado emitido por uma autoridade confiável ou termine o TLS em proxy reverso confiável.

## HTTP Basic Auth opcional

Basic Auth protege `POST /webhook`; `GET /healthz` permanece sem autenticação para monitoramento local. Ele fica desativado por padrão. Ative-o no `config.ini` local:

```ini
basic_auth_enabled = true
basic_auth_username = webhook
basic_auth_password_env = WEBHOOK_BASIC_AUTH_PASSWORD
basic_auth_password_file =
basic_auth_realm = Webhook Intake
```

Defina a senha no ambiente antes de iniciar o serviço:

```bash
export WEBHOOK_BASIC_AUTH_PASSWORD='use-um-segredo-longo-e-aleatorio'
python3 webhook.py --config config.ini
```

Envie uma requisição autenticada com:

```bash
curl -u webhook:"$WEBHOOK_BASIC_AUTH_PASSWORD" https://127.0.0.1:1604/webhook ...
```

Como alternativa, guarde somente um hash com sal da senha em arquivo local. Esta é a opção preferível quando uma variável de ambiente do processo não for adequada:

```bash
python3 webhook.py --create-basic-auth-password-file .faj383hfa
```

O comando pede a senha duas vezes e cria ou substitui o arquivo atomicamente com permissão `0600`. Configure-o no `config.ini`:

```ini
basic_auth_password_file = ./.faj383hfa
```

O arquivo usa PBKDF2-SHA256 com sal aleatório e é ignorado pelo Git. Quando `basic_auth_password_file` está definido, ele tem prioridade sobre `basic_auth_password_env`.

Basic Auth codifica as credenciais; ele não as cifra. O servidor se recusa a ativá-lo para listener HTTP fora do loopback, exceto quando `basic_auth_allow_insecure = true` é definido explicitamente. Use essa exceção somente em rede controlada ou quando proxy reverso confiável terminar o TLS e encaminhar o tráfego para loopback.

### Certificado de IP público com Certbot

Se um emissor exigir certificado publicamente confiável, mas conectar em um endereço IP público em vez de hostname, use o modo especial do Certbot. Ele exige Certbot 5.4 ou superior, IP estático globalmente roteável e TCP/80 de entrada disponível enquanto o Certbot realiza a validação ACME standalone:

```bash
sudo python3 webhook.py --config config.ini --certbot-mode \
  --certbot-ip 198.51.100.10 \
  --certbot-email admin@example.com
```

O script explica a operação e pede confirmação antes de contatar a autoridade certificadora. Em caso de sucesso, copia certificado e chave privada para `./tls/`, configura o `config.ini` para habilitar HTTPS e encerra sem iniciar o webhook. Use `--certbot-staging` para um teste inicial; o certificado emitido nesse modo não é publicamente confiável. `--certbot-yes` está disponível somente para uma execução não interativa deliberada.

Se `config.ini` não existir, o modo Certbot o cria a partir de `config.ini.example` antes de aplicar as configurações TLS.

Certificados de IP têm curta duração. Configure a renovação do Certbot e reinicie o webhook após a renovação para que ele carregue o certificado substituto. O diretório `tls/` gerado é ignorado pelo Git.

## Uso local

Na raiz do repositório, inicie o receptor com saída de depuração:

```bash
python3 webhook.py --config config.ini --debug
```

Em outro terminal, envie uma mensagem de teste:

```bash
curl -i http://127.0.0.1:1604/webhook \
  -H 'Content-Type: application/json' \
  -d '{"title":"Teste local","severity":"CRITICAL","body":"olá"}'
```

Com `tls_enabled = true`, use `https://` no lugar de `http://`. Adicione `-k` somente ao testar certificado autoassinado.

O perfil correspondente grava no diretório `output/` por padrão. Pare o receptor com `Ctrl+C`.

## Fluxo esperado da mensagem

```mermaid
flowchart LR
    Sender["Emissor de mensagens\ncompatível com webhook"] -->|"POST /webhook"| Receiver["Webhook Intake"]
    Receiver --> Check{"Caminho, tamanho e\nContent-Length válidos?"}
    Check -->|Não| Reject["Resposta HTTP de erro"]
    Check -->|Sim| Match["Lê JSON e aplica regras\nde origem + perfil"]
    Match -->|"Nenhum perfil normal"| Fallback["Perfil catch_all"]
    Match -->|"Um ou mais perfis"| Render["Formata raw, text,\nJSONL ou YAML"]
    Fallback --> Render
    Render --> Delivery{"Entrega do perfil"}
    Delivery -->|file| File["Acrescenta ao arquivo de saída"]
    Delivery -->|fifo| Pipe["Escreve no named pipe\nsem bloquear"]
    Delivery -->|both| File
    Delivery -->|both| Pipe
    File --> Consumers["Consumidores locais ou\noutras integrações"]
    Pipe --> Consumers
    Delivery --> Accepted["HTTP 202 Accepted"]
```

Em um perfil FIFO com `fifo_on_unavailable = fail`, uma falha de entrega obrigatória no pipe retorna HTTP 503 em vez de HTTP 202, permitindo nova tentativa por emissores que suportam retry.

## Perfis

Os perfis são avaliados na ordem do arquivo. Todas as regras de `match` de um perfil precisam corresponder. Uma mesma mensagem pode ir para mais de um arquivo; acrescente `stop_after_match = true` ao perfil caso queira parar após ele. Um perfil com `catch_all = true` só recebe mensagens que não casaram com nenhum perfil normal.

Uma regra tem uma chave de campo em notação pontuada e um valor. O valor pode ser uma string (igualdade) ou uma tabela com `equals`, `contains` ou `regex`. Use `catch_all = true` para o perfil de fallback. Para mensagens cujo `body` contém JSON em texto, caminhos como `body.metadata.severity` também funcionam.

Cada perfil possui:

- `file`: caminho relativo ao diretório `output_dir` (ou absoluto). Se `output_dir` não existir, ele é criado; se não for configurado, usa `./output` ao lado do arquivo de configuração;
- `format`: `raw`, `text`, `jsonl` ou `yaml`;
- `text_template` (somente `text`): template Python com campos da mensagem, como `{title}` ou `{body}`. Campos inexistentes ficam vazios.

## Diretório `profile.d`

O `config.ini` contém somente a configuração do servidor e define `profile_dir = ./profile.d`. Na inicialização, todos os arquivos `*.conf` desse diretório são lidos em ordem alfabética. Arquivos sem uma seção `[profile:nome]`, com sintaxe inválida ou perfil sem `file` são ignorados e geram um aviso, sem parar o webhook. Perfis dentro do `config.ini` são rejeitados para evitar configuração espalhada.

Use [profile.d/profile.conf.example](profile.d/profile.conf.example) como referência: ele contém todos os parâmetros possíveis e valores `dummy`. Copie-o para um arquivo com extensão `.conf`, defina `enabled = true` e ajuste os valores para ativá-lo.

`raw` conserva o corpo recebido. `jsonl` grava um valor JSON compacto por linha e requer arquivo `.jsonl` ou `.ndjson`; documentos `.json` convencionais não são suportados intencionalmente. `yaml` produz YAML simples sem biblioteca adicional e requer arquivo `.yaml` ou `.yml`. Se o corpo não for JSON, os formatos estruturados registram `{received_at, content_type, raw}`. Como cada entrega é acrescentada ao final do arquivo, escolha um arquivo por mensagem/formato ou `raw`/`text` se precisar de um fluxo contínuo.

## Entrega por arquivo ou FIFO

Cada perfil pode escolher `delivery = file` (padrão), `fifo` ou `both`. Para `fifo` e `both`, informe `fifo_path`; o named pipe é criado automaticamente. A escrita usa modo não bloqueante, portanto a ausência de um consumidor nunca congela o endpoint HTTP.

Use `fifo_on_unavailable = warn` (padrão) para registrar o evento em modo debug e continuar, ou `fail` para devolver HTTP 503 e permitir que o remetente tente novamente. Mensagens maiores que o limite atômico do FIFO (`PIPE_BUF`) são recusadas, evitando entregas parciais. `both` é recomendado quando o arquivo também deve servir como histórico confiável.

## Rotação de arquivos

Perfis com entrega em arquivo podem rotacionar a saída por tamanho antes que uma nova entrega ultrapasse o limite configurado:

```ini
rotate_max_bytes = 10485760
rotate_keep = 10
rotation_mode = rename
```

`rotate_max_bytes` é medido em bytes; `0` desativa a rotação. `rotate_keep` define quantos arquivos arquivados serão mantidos. Os arquivos são arquivados ao lado do arquivo ativo, por exemplo `critical.20260703T143000Z.001.jsonl`.

A rotação fica ativa por padrão para todo perfil com `file` ou `both`: `rotate_max_bytes = 10485760` (10 MiB), `rotate_keep = 10` e `rotation_mode = rename`. O perfil pode sobrescrever qualquer um desses valores. Defina `rotate_max_bytes = 0` explicitamente para desativar a rotação somente naquele perfil.

Há dois modos de rotação:

- `rename` (recomendado): renomeia o arquivo ativo para um arquivo arquivado e cria um novo arquivo ativo na próxima escrita. Isso preserva o inode antigo para que consumidores corretos terminem sua leitura. Os consumidores devem acompanhar o nome do arquivo (`tail -F`) ou detectar a mudança de inode e reabrir o arquivo ativo.
- `copytruncate`: copia o arquivo ativo para um arquivo arquivado e, depois, trunca esse mesmo arquivo. Isso favorece consumidores legados que usam `tail -f` em um caminho fixo, mas um consumidor lento pode perder dados que ainda não tinha lido antes do truncamento. Não use quando o consumo exatamente uma vez for necessário.

A rotação ocorre sob o lock de escrita do webhook, portanto as próprias escritas do webhook não se misturam à rotação. Para consumidores que precisam de entrega imediata, use `delivery = both` e trate o JSONL rotacionado como histórico durável.

## Identificação por origem

Além das regras sobre o conteúdo da mensagem, cada perfil pode restringir a **origem de rede** recebida:

```ini
[profile:origem-confiavel]
file = messages.raw
format = raw
origin_cidr = 10.0.0.0/24
```

Use `origin` para um IP exato, `origin_cidr` para uma faixa CIDR, ou `origin_regex` para uma expressão regular. Todos os critérios do perfil precisam corresponder. A origem padrão é o IP que abriu a conexão TCP. Caso exista um proxy reverso confiável na frente do webhook, ative `trust_forwarded_for = true` para considerar o primeiro IP de `X-Forwarded-For`; não ative essa opção ao expor o serviço diretamente.

## Exemplo de envio

```bash
curl -i http://127.0.0.1:1604/webhook \
  -H 'Content-Type: application/json' \
  -d '{"title":"CPU alta","severity":"CRITICAL","body":"instância vm-01"}'
```

## Testes

O diretório `tests/` contém testes automatizados do carregamento de configurações, perfis, filtros de origem, escrita de arquivos e endpoint HTTP. Eles evitam regressões quando o webhook ou seus perfis forem alterados.

```bash
python3 -m unittest discover -s tests -v
```

Também é possível executar o arquivo de teste diretamente:

```bash
python3 tests/test_webhook.py
```

## GitHub

O repositório inclui `.gitignore` para não versionar mensagens recebidas, caches e ambientes locais, além de um workflow em `.github/workflows/tests.yml` que executa os testes em cada push e pull request.

## Licença

Este projeto é licenciado sob a [Apache License 2.0](LICENSE).
