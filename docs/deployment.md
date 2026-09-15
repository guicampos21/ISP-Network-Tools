# Implantação

## Preparação

Instale Docker Engine com Compose v2 e mantenha o Nginx Proxy Manager já existente. A stack não cria nem configura um novo NPM. O NPM precisa compartilhar a rede Docker externa definida por `PROXY_NETWORK` (por padrão, `npm_default`) e encaminhar os hosts configurados para as portas internas dos containers.

```bash
cp .env.example .env
./scripts/bootstrap-secrets.sh
docker network inspect npm_default
docker compose config --quiet
```

Edite `.env` antes da primeira subida. Defina os hosts públicos, `COMPANY_NAME`, `SUITE_NAME`, `TRUSTED_HOSTS`, e os identificadores OIDC. Em produção use `APP_ENV=production`, `DEV_AUTH=false` e HTTPS terminado no NPM.

## Segredos

O arquivo `.env` contém somente configuração não sensível. Os valores sensíveis ficam em `SECRETS_DIR`, normalmente `/opt/isp-network-tools/secrets` em produção. Esse diretório deve ter modo `0700`; cada arquivo deve ter modo `0600`, pertencer ao usuário que executa o Compose e conter uma única linha sem aspas. Como o Compose local monta arquivos de segredo preservando o proprietário do host, os entrypoints dos serviços copiam esses arquivos para `/tmp` com modo `0400`, ajustam o proprietário do processo e descartam os privilégios antes de iniciar a aplicação.

```bash
install -d -m 700 /opt/isp-network-tools/secrets
SECRETS_DIR=/opt/isp-network-tools/secrets ./scripts/bootstrap-secrets.sh
chmod 600 /opt/isp-network-tools/secrets/*
```

O script gera as senhas do PostgreSQL, as chaves de sessão, a chave de assinatura SSO e o token de bootstrap. Os arquivos `entra_client_secret` e `google_client_secret` são criados vazios para serem preenchidos manualmente pelo operador. Nunca coloque esses arquivos no repositório, em uma imagem Docker, em backup público ou em chamado.

Para alterar uma senha, gere um novo valor em arquivo temporário protegido, atualize primeiro a credencial no PostgreSQL, substitua o arquivo correspondente e reinicie os serviços que o consomem. Para rotacionar `SSO_SIGNING_SECRET`, faça uma janela coordenada porque os dois serviços precisam trocar para o mesmo valor. Guarde os valores no cofre operacional adotado pela instalação; o arquivo local é apenas a fonte montada pelo Compose.

## Primeira subida

```bash
docker compose -f compose.yaml -f compose.prod.yaml up -d --build
docker compose ps
docker compose logs --tail=100 postgres admin-center isp-network-health
```

Abra o host do Admin Center. O fluxo `/setup` aceita o token armazenado em `setup_token` e cria o primeiro SuperAdmin local. Depois do login, configure TOTP, OIDC, branding, usuários, grupos e acesso ao ISP Network Health. Remova ou substitua o token de bootstrap após o uso e reinicie o Admin Center.

## NPM

Crie ou ajuste no NPM três proxies para os hosts público, administrativo e Health, apontando para `geofeed-public:8080`, `admin-center:8080` e `isp-network-health:8090` na mesma rede Docker. Configure TLS, redirecionamento HTTPS e os cabeçalhos de segurança no NPM conforme a política do ambiente.

## Backup e restauração

O backup é responsabilidade do operador e deve ser externo à stack. Inclua o volume PostgreSQL, os volumes `admin_data`, `admin_backups`, `geofeed_publish`, e os segredos protegidos necessários para a restauração. Teste a restauração em uma instalação isolada antes de qualquer troca de tráfego.

## Atualização

Faça pull ou copie a versão revisada, execute `make check`, valide a configuração e suba novamente os serviços. Preserve os volumes. Migrações de dados devem seguir [migration.md](migration.md) e ter plano de retorno antes da troca no NPM.
