# Vocabulário do domínio

## ISP Network Tools

Suíte de ferramentas para operação de provedores de acesso, formada por um
portal administrativo, IPAM/Geofeed, ISP Network Health e Geofeed público.

## Admin Center

Área central de identidade, usuários, grupos, permissões, configurações
globais, auditoria e cadastros mestres.

## Empresa

Uma empresa do próprio grupo operador que detém ou administra blocos IP e
ASNs. Empresa não é cliente e não representa uma pessoa que acessa o sistema.

## Cliente

Uma organização ou pessoa atendida pelo operador. Um cliente pode receber
recursos de rede e possuir contatos, endereço e associações a vários itens
ativos do Catálogo de Serviços.

## POP

Um ponto de presença físico ou data center da rede, com localização, contatos,
janela de acesso e autonomia energética. O cadastro mestre de POPs/DCs pertence
ao Admin Center; o IPAM apenas associa esses registros às alocações. Um POP/DC
pode concentrar vários recursos IP e serviços.

## IPAM/Geofeed

Área responsável pelo inventário e pela alocação de endereços, blocos, ASNs,
VRFs e VLANs, além do fluxo de publicação do Geofeed. O IPAM associa recursos
às Empresas, aos Clientes e aos POPs/DCs cadastrados no Admin Center, conforme
o caso.

## Geofeed público

Visualização pública da publicação aprovada. Seu contrato atual permanece
limitado às informações de prefixo, país, região, cidade e código postal.

## ISP Network Health

Área de análises operacionais, consultas de reputação, blacklists e relatórios
sobre recursos de rede.

## Usuário e grupo

Usuário é uma identidade que acessa a suíte. Grupo é uma coleção de usuários
que pode receber permissões e aplicações em conjunto. Cliente não é usuário.
