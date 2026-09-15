# Arquitetura

O monorepo mantém três aplicações com limites de execução separados e um cluster PostgreSQL com bancos lógicos por contexto. O Geofeed público não recebe credenciais do banco. O Admin Center é a autoridade de identidade, autorização e publicação. O ISP Network Health tem web e worker próprios.

```mermaid
flowchart LR
  NPM["NPM existente<br/>TLS e roteamento"] --> PUBLIC["geofeed-public<br/>Nginx"]
  NPM --> ADMIN["admin-center<br/>Flask/Gunicorn"]
  NPM --> HEALTH["isp-network-health<br/>Flask/Gunicorn"]
  ADMIN --> PG["PostgreSQL<br/>isp_core / geofeed / isp_network_health"]
  ADMIN --> REDIS["Redis<br/>fila interna"]
  ADMIN --> FEED["volume de publicação"]
  ADMINW["admin-center-worker"] --> PG
  ADMINW --> FEED
  PUBLIC --> FEED
  HEALTH --> PG
  HEALTH --> REDIS
  HEALTHW["health-worker"] --> PG
  HEALTHW --> REDIS
```

## Limites de cada aplicação

### Geofeed público

O container contém HTML, configuração Nginx e o volume aprovado montado como somente leitura. Aceita apenas GET e não possui sessão, banco ou endpoint administrativo.

### Admin Center

O código recuperado do portal Geofeed continua sendo a base do Admin Center. Durante a transição, o banco autoritativo inicial é `isp_core`, pois identidade, configurações, autorização e domínio Geofeed ainda compartilham a mesma sessão SQLAlchemy. O banco lógico `geofeed` é criado desde o primeiro boot e será usado na extração versionada seguinte.

### ISP Network Health

O pacote `src/inh` é preservado como núcleo de regras e coleta. A web não importa o CLI para responder HTTP. O worker é a fronteira para DNSBL, RDAP, WHOIS, ping e outras probes, com timeout, validação de destino e resultados persistidos em `isp_network_health`.

## Regras para novas aplicações

Uma nova aplicação deve ficar em `apps/`, expor healthcheck interno, usar os tokens visuais compartilhados, validar entitlement no servidor, receber somente seus bancos e segredos, entrar no Compose com rede interna e proxy externo, e incluir testes, documentação e revisão de segurança.
