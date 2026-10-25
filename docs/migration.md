# Migração

O Geofeed foi encontrado em `/home/guilherme/Projects/geofeed-admin`, sem histórico Git local. O INH foi encontrado em `/home/guilherme/git/INH`, na tag `v1.0.0`. A consolidação copia os fontes sem dados de produção, arquivos de estágio, cache ou segredos.

## Dados do Geofeed

Antes de escrever no novo PostgreSQL:

1. pare ou coloque a instalação antiga em modo controlado;
2. faça uma cópia somente leitura do SQLite e calcule seu hash;
3. valide tabelas, contagens, vínculos e o snapshot publicado;
4. simule a importação de usuários, papéis, configurações, auditoria, empresas, blocos, entradas, alterações, publicações e notificações;
5. preserve os identificadores Entra ID e Google;
6. importe em transação e valide novamente o feed;
7. só então altere o tráfego no NPM.

A conta inicial não usa senha padrão. Se a importação trouxer um SuperAdmin válido, o bootstrap de instalação deve permanecer desabilitado. Caso contrário, crie-o pelo fluxo `/setup` com o token externo.

### Execução da importação

O comando lê o SQLite em modo somente leitura e grava no PostgreSQL do Admin
Center. Primeiro execute a simulação; os totais devem ser comparados com o
inventário da origem:

```bash
docker compose exec -T admin-center flask --app wsgi:app \
  import-legacy-sqlite --source /tmp/geofeed-admin.sqlite3
docker compose exec -T admin-center flask --app wsgi:app \
  import-legacy-sqlite --source /tmp/geofeed-admin.sqlite3 --apply
docker compose exec -T admin-center flask --app wsgi:app validate-working
```

O comando é idempotente para usuários, empresas, blocos, entradas, histórico
de publicações, auditoria e notificações. Hashes de contas locais são
preservados; sessões e tokens de sessão não são migrados. Segredos de SMTP,
Entra ID e Google não são lidos pelo importador: eles devem ser colocados
manualmente nos arquivos protegidos de `SECRETS_DIR`. O snapshot publicado e o
estado de trabalho são preservados e a rotina não executa publicação automática.

O banco `isp_network_health` é separado. Os registros legados de
`health_checks` pertencem ao histórico do Geofeed e são importados para o
Admin Center; o histórico de scans do novo Network Health começa vazio, pois
não existe uma tabela legada equivalente.

## Bancos lógicos

O primeiro boot cria `isp_core`, `geofeed` e `isp_network_health` no mesmo cluster. A base recuperada continua usando `isp_core` na fase de compatibilidade. A extração das tabelas Geofeed para `geofeed` deve ser uma migração versionada, porque o modelo atual usa relacionamentos dentro de uma sessão SQLAlchemy única.

As tabelas legadas `ipam_customers` e `ipam_pops` são renomeadas automaticamente no primeiro boot para `customers` e `pops_dcs`. A operação preserva os identificadores e os vínculos das alocações; confirme os nomes e as contagens no banco antes de liberar o tráfego.

## Fechamento dos repositórios antigos

Depois da validação funcional, da restauração de backup e da troca de tráfego, arquive o repositório INH e a cópia antiga do Geofeed conforme a política da equipe. O monorepo `ISP Network Tools` passa a ser a fonte de desenvolvimento.
