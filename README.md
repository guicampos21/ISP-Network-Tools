# ISP Network Tools

ISP Network Tools é uma suíte white label para operações de provedores de internet. O portal abre no Geofeed público e oferece um lançador para as aplicações protegidas:

- **Geofeed público:** feed aprovado e downloads públicos;
- **Admin Center:** administração do Geofeed, usuários, grupos, permissões, aprovações, publicação, auditoria e identidade visual;
- **ISP Network Health:** aplicação web para análises de domínios, IPv4, CIDR e ASN, baseada no núcleo recuperado do INH.

O projeto é um monorepo. Cada aplicação e o PostgreSQL executam em containers separados. O Nginx Proxy Manager existente permanece externo e é conectado pela rede Docker configurada em `.env`.

## Fontes consolidadas

O código foi recuperado de `/home/guilherme/Projects/geofeed-admin` e `/home/guilherme/git/INH`. A cópia não inclui dados de produção, arquivos de estágio, cache ou segredos. O nome público e o serviço Docker são `admin-center`; o pacote Python legado `geofeed_admin` permanece temporariamente para preservar a compatibilidade interna.

## Estrutura

```text
apps/admin-center/          Portal administrativo Flask/Jinja recuperado
apps/geofeed-public/        Nginx para artefatos públicos aprovados
apps/isp-network-health/    Web, worker e núcleo Python do INH
infra/postgres/init/        Criação dos bancos lógicos e usuários
infra/secrets/               Instruções; nenhum segredo real
packages/                    Contratos e componentes compartilhados
docs/                        Arquitetura, implantação, segurança e migração
scripts/                     Operação local e verificações
compose.yaml                 Base comum
compose.prod.yaml            Endurecimento de produção
```

## Ambiente de teste

Requisitos: Docker Compose v2, OpenSSL e a rede Docker externa já usada pelo NPM.

```bash
cp .env.example .env
./scripts/bootstrap-secrets.sh
docker network inspect npm_default
docker compose config
docker compose up --build
```

No primeiro acesso, abra o host do Admin Center e use o fluxo de bootstrap para criar o primeiro SuperAdmin local. Não existe senha padrão. Os detalhes de segredos, URLs, NPM, migração e produção estão em [docs/deployment.md](docs/deployment.md).

## Desenvolvimento

```bash
make check
make test
make compose-config
```

O núcleo recuperado do INH continua testável sem acessar a rede; a camada web e o worker são evoluídos separadamente.

Os relatórios do Network Health começam com um resumo compacto por endereço IP. Os resultados ficam organizados por bloco, com a lista completa de blacklists disponível ao passar o mouse ou usar o foco; o botão **Gerar PDF** produz o documento internamente com expansão automática dos blocos que possuem detecção. Consulte [docs/health-reporting.md](docs/health-reporting.md).

## Segurança

O baseline cobre autenticação recuperada, autorização no servidor, CSRF, cookies seguros, hosts confiáveis, CSP, rate limiting, segredos externos, containers sem root, rede interna e publicação atômica. O mapa de riscos e as pendências estão em [docs/security-review.md](docs/security-review.md).

## Licença

O código consolidado permanece sob GPL-3.0-or-later. Consulte [LICENSE](LICENSE) e [CONTRIBUTING.md](CONTRIBUTING.md).
