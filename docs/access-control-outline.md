# Esboço de usuários, perfis e grupos

## Decisão proposta

O Admin Center será a autoridade única de identidade e autorização da suíte.
Cada usuário terá um único perfil obrigatório. O perfil será responsável por
definir:

- quais aplicações o usuário pode abrir;
- quais telas pode consultar;
- quais operações pode executar;
- se pode aprovar, publicar ou administrar a suíte.

Grupos continuarão existindo, mas terão função organizacional. Eles não
concedem, removem ou alteram permissões e não influenciam a abertura das
aplicações.

Não haverá permissões individuais nem exceções de aplicação por usuário.
Quando uma pessoa precisar de uma combinação diferente de acessos, o
SuperAdmin deverá atribuir outro perfil ou criar um perfil operacional
apropriado.

## Modelo funcional

### Usuário

O usuário representa a identidade que acessa a suíte e mantém os dados de
autenticação existentes:

- conta local, Microsoft Entra ID ou Google;
- e-mail e identificadores externos;
- status ativo ou inativo;
- um perfil obrigatório;
- um grupo opcional;
- último acesso e dados de auditoria.

Cada usuário poderá pertencer a no máximo um grupo. Desativar o usuário ou seu
perfil deve bloquear imediatamente o acesso às aplicações protegidas.

### Perfil

O perfil é o conjunto de permissões efetivas. Ele deve possuir código, nome,
descrição, status e indicação de perfil protegido pelo sistema.

O acesso à aplicação será tratado como uma permissão do perfil, por exemplo:

```text
app.admin_center.access
app.ipam_geofeed.access
app.isp_network_health.access
```

As demais permissões seguem o mesmo padrão, agrupadas por área:

```text
dashboard.view
audit.view
catalog.companies.view
catalog.companies.manage
catalog.customers.view
catalog.customers.manage
catalog.pops.view
catalog.pops.manage
catalog.services.view
catalog.services.manage
ipam.view
ipam.private.manage
ipam.public.submit
ipam.public.approve
ipam.public.reject
ipam.publish
health.view
health.run
health.report.export
users.manage
profiles.manage
groups.manage
settings.manage
```

O Geofeed público continua público e não precisa de permissão de usuário.

## Política de cadastro do IPAM

O usuário não escolhe se o recurso é público ou privado. O IPAM calcula o
escopo a partir do endereço informado:

- IPv4 RFC 1918 e IPv6 ULA são classificados como privados;
- endereços globalmente roteáveis são classificados como públicos;
- endereços especiais, reservados, multicast, loopback e link-local ficam em
  uma categoria técnica separada e não podem ser cadastrados como públicos;
- recursos derivados devem manter o mesmo escopo do bloco pai.

O perfil Operador IPAM poderá cadastrar e alterar recursos privados
imediatamente. Essas alterações ficam disponíveis no inventário após a
validação e entram na auditoria.

Recursos públicos serão criados como pendentes. O cadastro poderá ser salvo e
revisado, mas não poderá ser usado para publicação enquanto não houver
aprovação. A mesma regra deve valer para alterações estruturais e
desativação de recursos públicos, evitando que uma alteração posterior escape
do fluxo de aprovação.

O fluxo mínimo será:

```text
privado  -> ativo imediatamente
público  -> pendente -> aprovado ou rejeitado
especial -> bloqueado para operação pública
```

O estado de aprovação deve ser separado do estado operacional do recurso. Um
recurso pode estar `aprovado` e `disponível`, ou `aprovado` e `alocado`.
Recomenda-se reutilizar o fluxo de `change_requests` para guardar a proposta,
o snapshot, o solicitante, o revisor, a decisão e as observações. O registro
IPAM deve manter uma referência à solicitação aprovada para impedir publicação
de dados que não passaram pelo fluxo.

Recomenda-se que `Administrador` e `SuperAdmin` possam aprovar recursos
públicos, com uma regra obrigatória de que o solicitante não aprove a própria
alteração. Se a operação exigir segregação mais rígida, a permissão
`ipam.public.approve` pode ficar exclusiva do SuperAdmin sem alterar o modelo.

O Geofeed somente poderá considerar recursos públicos aprovados e continuará
publicando apenas as cinco colunas atuais da RFC 8805. Dados de cliente, POP,
endereço físico, GPS, VLAN e VRF nunca entram no arquivo público.

### Grupo

O grupo terá somente:

- nome;
- descrição;
- status;
- membros;
- datas de criação e alteração.

O grupo poderá ser usado para filtrar usuários, organizar equipes, exibir
informações no painel e preparar futuras funcionalidades de comunicação. Ele
não poderá possuir permissões, aplicações ou regras de autorização.

## Perfis iniciais recomendados

Para evitar uma matriz complexa, a instalação deve começar com estes perfis
protegidos:

| Perfil | Aplicações | Responsabilidade |
|---|---|---|
| SuperAdmin | Todas | Segurança, usuários, perfis, configurações e operação completa |
| Administrador | Admin Center, IPAM/Geofeed e Network Health | Administração operacional, cadastros, aprovações e relatórios |
| Operador IPAM | Admin Center e IPAM/Geofeed | Inventário, alocações, cadastros operacionais e propostas |
| Operador Network Health | Admin Center e ISP Network Health | Execução de scans, análise e relatórios de saúde |
| Consulta | Aplicações liberadas para consulta | Leitura sem alteração ou publicação |

O perfil Consulta deve receber somente permissões de leitura. O Admin Center
deve permitir perfis personalizados no futuro, mas a primeira versão deve
priorizar os perfis protegidos acima para evitar combinações difíceis de
auditar.

## Regras administrativas

- Somente SuperAdmin pode criar, editar, desativar e excluir usuários.
- Somente SuperAdmin pode criar, editar, desativar e excluir perfis.
- Somente SuperAdmin pode atribuir ou alterar o perfil de um usuário.
- Somente SuperAdmin pode administrar grupos.
- Perfis protegidos não podem ser excluídos.
- Deve existir sempre pelo menos um SuperAdmin ativo.
- O SuperAdmin não pode remover o próprio acesso se for o último SuperAdmin.
- Administrador pode operar cadastros e fluxos autorizados pelo perfil, mas não
  pode alterar a estrutura de autorização.
- Alterações de usuário, perfil, grupo e permissões entram na Auditoria.
- A autorização é verificada no servidor em toda rota, ação e aplicação; o
  menu apenas reflete o resultado dessa verificação.

## Modelo de dados recomendado

O novo PostgreSQL deve usar uma estrutura explícita:

```text
users
  profile_id -> profiles.id
  group_id   -> groups.id, nullable

profiles
  id, code, name, description, system, active

permissions
  id, code, name, description, application_code, active

profile_permissions
  profile_id -> profiles.id
  permission_id -> permissions.id

groups
  id, name, description, active
```

As tabelas `user_application_grants` e `group_application_grants` deixam de
existir no modelo novo. A tabela `applications` pode continuar existindo para
o catálogo e o lançador, mas não terá uma matriz de concessões; o acesso será
determinado por `permissions` do perfil.

## Comportamento do lançador de aplicações

O lançador deve exibir:

- Geofeed público para todos, abrindo em nova aba;
- Admin Center para usuários com `app.admin_center.access`;
- IPAM/Geofeed para usuários com `app.ipam_geofeed.access`;
- ISP Network Health para usuários com `app.isp_network_health.access`.

A aplicação também deve validar a permissão no servidor. Esconder um ícone no
lançador nunca será considerado controle de acesso.

## SSO entre aplicações

O Admin Center continuará sendo a autoridade de login. O handoff para o ISP
Network Health deve carregar um identificador do usuário, o perfil, o público
de destino, a expiração curta e a autorização assinada pelo Admin Center.

O Network Health não deve aceitar um perfil informado pelo navegador nem
manter uma segunda tabela editável de usuários. O token deve ser assinado,
consumido uma única vez e validado no servidor.

## Migração do Geofeed de produção

Durante a importação:

- `super_admin` será convertido em SuperAdmin;
- `admin` será convertido em Administrador;
- `editor` será convertido inicialmente em Operador IPAM, sujeito à revisão;
- `entra_oid`, `tenant_id`, `google_sub`, hashes de senha e configurações de
  MFA serão preservados quando existentes;
- sessões ativas não serão migradas;
- grupos e concessões individuais antigos não serão importados como regras,
  pois o modelo novo não utilizará essas exceções;
- o usuário Microsoft sem `entra_oid` deverá ficar pendente de revisão antes
  da liberação do novo ambiente.

Depois da importação, o SuperAdmin deverá revisar o perfil de cada usuário e
criar os grupos organizacionais necessários. A migração não deve liberar
automaticamente aplicações com base apenas no e-mail ou no grupo.

## Alteração prevista no código

O código atual possui `Role`, permissões em JSON e concessões diretas por
usuário ou grupo. A reestruturação deve:

1. apresentar `Role` como `Perfil` na interface;
2. migrar as permissões para o catálogo e a relação de perfil;
3. substituir `user.role` por `user.profile_id`;
4. remover a avaliação de permissões por grupo;
5. remover as concessões diretas de aplicação;
6. centralizar a decisão em `current_user.has_permission(...)`;
7. manter compatibilidade temporária apenas durante a migração de dados.

Essa mudança deve ser concluída antes da importação definitiva para produção.
