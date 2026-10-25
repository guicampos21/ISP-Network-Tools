# Implantação

## Preparação

Instale Docker Engine com Compose v2 e mantenha o Nginx Proxy Manager já existente. A stack não cria nem configura um novo NPM. O NPM precisa compartilhar a rede Docker externa definida por `PROXY_NETWORK` (por padrão, `npm_default`) e encaminhar os hosts configurados para as portas internas dos containers.

```bash
cp .env.example .env
./scripts/bootstrap-secrets.sh
docker network inspect npm_default
docker compose -p ${COMPOSE_PROJECT_NAME:-isp-network-tools} config --quiet
```

Edite `.env` antes da primeira subida. Defina os hosts públicos, `COMPANY_NAME`, `SUITE_NAME`, `TRUSTED_HOSTS`, os identificadores OIDC e a rede Docker já compartilhada pelo NPM. Em produção use `APP_ENV=production`, `DEV_AUTH=false` e HTTPS terminado no NPM.

## Segredos

O arquivo `.env` contém somente configuração não sensível. Os valores sensíveis ficam em `SECRETS_DIR`, normalmente `/opt/isp-network-tools/.local/secrets` em produção. Esse diretório deve ter modo `0700`; cada arquivo deve ter modo `0600`, pertencer ao usuário que executa o Compose e conter uma única linha sem aspas. Como o Compose local monta arquivos de segredo preservando o proprietário do host, os entrypoints dos serviços copiam esses arquivos para `/tmp` com modo `0400`, ajustam o proprietário do processo e descartam os privilégios antes de iniciar a aplicação.

```bash
install -d -m 700 /opt/isp-network-tools/.local/secrets
SECRETS_DIR=/opt/isp-network-tools/.local/secrets ./scripts/bootstrap-secrets.sh
chmod 600 /opt/isp-network-tools/.local/secrets/*
```

O script gera as senhas do PostgreSQL, as chaves de sessão, a chave de assinatura SSO e o token de bootstrap. Os arquivos `entra_client_secret` e `google_client_secret` são criados vazios para serem preenchidos manualmente pelo operador. Nunca coloque esses arquivos no repositório, em uma imagem Docker, em backup público ou em chamado.

Para alterar uma senha, gere um novo valor em arquivo temporário protegido, atualize primeiro a credencial no PostgreSQL, substitua o arquivo correspondente e reinicie os serviços que o consomem. Para rotacionar `SSO_SIGNING_SECRET`, faça uma janela coordenada porque os dois serviços precisam trocar para o mesmo valor. Guarde os valores no cofre operacional adotado pela instalação; o arquivo local é apenas a fonte montada pelo Compose.

## Primeira subida

```bash
docker compose -p isp-network-tools-prod -f compose.yaml -f compose.prod.yaml up -d --build
docker compose -p isp-network-tools-prod ps
docker compose -p isp-network-tools-prod logs --tail=100 postgres admin-center isp-network-health
```

Abra o host do Admin Center. O fluxo `/setup` aceita o token armazenado em `setup_token` e cria o primeiro SuperAdmin local. Depois do login, configure TOTP, OIDC, branding, usuários, grupos, os cadastros mestres de Empresas, Clientes e POPs/DCs, e o acesso ao IPAM/Geofeed e ao ISP Network Health. O SuperAdmin controla cada aplicação protegida em **Configurações → Aplicações e grupos**; o IPAM/Geofeed usa o mesmo host e sessão do Admin Center em `/ipam` e consome os cadastros mestres. Remova ou substitua o token de bootstrap após o uso e reinicie o Admin Center.

## NPM

Crie ou ajuste no NPM dois proxies: o host público apontando para `geofeed-public:8080` e o host administrativo apontando para `admin-center:8080`, na mesma rede Docker. Dentro do proxy administrativo, crie uma localização `/network-health/` apontando para `isp-network-health:8090`. O endereço do Network Health será, portanto, `https://<host-do-admin>/network-health`; não é necessário um DNS ou proxy separado para ele. Na instalação atual, confirme a rede compartilhada com `docker network inspect` e use esse nome em `PROXY_NETWORK`; não presuma `npm_default`. Configure TLS, redirecionamento HTTPS e os cabeçalhos de segurança no NPM conforme a política do ambiente.

Depois de recriar o container `isp-network-health`, valide o acesso por `/network-health/`. Se o NPM retornar 502 enquanto o serviço estiver saudável, ele pode estar usando o IP anterior do container. No host do NPM, execute `docker exec nginx-proxy-manager nginx -t` e, se a configuração estiver válida, `docker exec nginx-proxy-manager nginx -s reload` para atualizar a resolução do nome Docker.

## Backup e restauração

O backup é responsabilidade do operador e deve ser externo à stack. Inclua o volume PostgreSQL, os volumes `admin_data`, `admin_backups`, `geofeed_publish`, e os segredos protegidos necessários para a restauração. Teste a restauração em uma instalação isolada antes de qualquer troca de tráfego.

## Atualização

Faça pull ou copie a versão revisada, execute `make check`, valide a configuração e suba novamente os serviços. Preserve os volumes. Migrações de dados devem seguir [migration.md](migration.md) e ter plano de retorno antes da troca no NPM.

## Saída de rede dos coletores

O PostgreSQL e o Redis ficam exclusivamente na rede interna `backend`.
O worker do ISP Network Health também participa de `collector-egress`, uma
rede sem portas publicadas que permite consultas DNS e HTTPS de saída.
Não remova essa rede do worker: sem ela, todas as consultas externas podem
terminar em timeout mesmo quando o painel web permanece acessível.

Para validar a coleta após a implantação:

```sh
docker compose exec isp-network-health-worker dig +time=3 +tries=1 2.0.0.127.bl.spamcop.net
```

O endereço `127.0.0.2` é permitido para testes DNSBL. Uma resposta
`127.255.255.254` do Spamhaus é uma recusa devido à política do resolvedor,
não uma detecção; o relatório apresenta a consulta como inconclusiva.
Use um resolvedor recursivo compatível com a política do provedor ou seu
serviço DQS para obter respostas autorizadas do Spamhaus.
O implantador pode definir `HEALTH_DNS_SERVER=<IP-do-resolvedor>` em `.env`
para escolher o DNS utilizado nas consultas de blacklist. A variável aceita
somente um endereço IPv4 ou IPv6. Após alterá-la, recrie o worker. Uma resposta
SERVFAIL/REFUSED é apresentada como erro, e não como ausência de listagem.

Em instalações importadas que ainda não possuem inventário IPAM, integre os
blocos já aprovados no Geofeed depois de fazer backup do PostgreSQL:

```sh
docker compose exec admin-center flask --app wsgi:app import-geofeed-inventory
```

O comando pode ser repetido: não duplica prefixos nem sobrescreve alocações
existentes. Mantém o vínculo com a empresa e o bloco de origem e registra a
importação na auditoria. Não modifica nem republica os arquivos do Geofeed e
não infere clientes, POPs/DCs ou ocupação dos endereços.
