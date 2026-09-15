# Pacotes compartilhados

Este diretório guarda contratos que devem ser iguais entre as aplicações: tokens de identidade visual, componentes de acessibilidade, formato do handoff SSO e convenções de eventos.

O Admin Center continua sendo a fonte do tema configurado pelo implantador. Cada aplicação deve aceitar `SUITE_NAME`, `COMPANY_NAME` e suas URLs por configuração, sem referências a uma empresa específica no código ou nas imagens.

Ao transformar um contrato em código compartilhado, inclua testes unitários e copie somente o pacote necessário para cada imagem Docker. O pacote não deve acessar diretamente bancos ou segredos de outra aplicação.
