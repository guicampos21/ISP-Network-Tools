# Revisão de segurança inicial

Este mapa usa o OWASP Top 10 como baseline. A revisão foi aplicada ao primeiro corte funcional da suíte; os itens marcados como pendentes continuam sendo gates para produção.

| OWASP | Controle | Estado |
| --- | --- | --- |
| A01 Controle de acesso quebrado | Papéis atuais, entitlement por aplicação e autorização no servidor | Implementado no corte atual; revisar matriz com cada IdP |
| A02 Falhas criptográficas | TLS no NPM, cookies seguros, segredos externos e TOTP | Baseline implementado; TLS depende do NPM |
| A03 Injeção | ORM, queries parametrizadas, validação de entrada e subprocessos controlados | Implementado no corte atual; SCA pendente |
| A04 Design inseguro | Bootstrap único, deny by default, bancos separados e worker | Implementado; migração Geofeed dedicada pendente |
| A05 Configuração insegura | Hosts confiáveis, CSP, headers, containers sem root e NPM externo | Baseline criado |
| A06 Componentes vulneráveis | Dependências fixadas, SCA e revisão das imagens | Pendente: executar SCA e fixar imagens por digest |
| A07 Falhas de identificação | Entra, Google, local, sessão rotativa, TOTP e rate limit | Implementado no corte atual; IdPs reais pendentes |
| A08 Integridade de software | CI, secret scan, revisão de imagem e migrações versionadas | Base criada |
| A09 Falhas de logging | Auditoria recuperada, logs sem credenciais e eventos de worker | Implementado no corte atual; retenção externa pendente |
| A10 SSRF | Bloqueio de destinos privados, timeout, DNS rebinding e egress mínimo | Validação de destinos e timeouts implementados; política de egress pendente |

## Regras obrigatórias

- esconder uma aplicação no lançador nunca substitui autorização de rota ou API;
- o Geofeed público não recebe credenciais PostgreSQL;
- `DEV_AUTH` só pode existir em desenvolvimento;
- hosts aceitos vêm de configuração controlada;
- uploads validam tipo, assinatura, tamanho e caminho;
- logs não contêm senha, token, segredo OIDC ou conteúdo de sessão;
- o worker rejeita loopback, link-local, multicast e redes privadas antes de DNS, socket, ping ou subprocesso;
- toda alteração de estado exige CSRF e autorização explícita.

## Gates antes da publicação

1. configurar e testar os IdPs reais e o TLS no NPM;
2. executar SCA e fixar versões de imagens por digest;
3. separar as tabelas Geofeed para o banco dedicado com migração versionada;
4. ampliar testes negativos para BOLA/IDOR, CSRF, SSRF, host header e upload;
5. definir retenção externa de logs e procedimento de restauração;
6. executar revisão final das imagens e teste de carga do worker.
