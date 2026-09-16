# Alternativas visuais da suíte

O tema aplicado nesta entrega é **Obsidian + Signal**. Ele mantém a identidade roxa atual do Geofeed Admin Center, mas separa melhor o fundo, os cartões, os cabeçalhos de tabela e os contornos. A mesma hierarquia visual foi aplicada ao Admin Center, ao Geofeed público e ao ISP Network Health.

## Tema aplicado: Obsidian + Signal

| Token | Valor | Uso |
| --- | --- | --- |
| `--bg` | `#0B0910` | Fundo da aplicação |
| `--surface` | `#17131F` | Cartões e áreas de conteúdo |
| `--surface-2` | `#241B31` | Cabeçalhos, campos e métricas clicáveis |
| `--surface-3` | `#302340` | Hover, popovers e estados selecionados |
| `--border` | `#58456B` | Contornos e separadores |
| `--border-strong` | `#7A6090` | Foco e contornos de interação |
| `--muted` | `#C7BDD2` | Texto secundário |
| `--success` | `#69DFA5` | Usuários online, RFC válida e sucesso |

### Exemplo de Visão geral

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ ●  Admin Center             Visão geral  Empresas  Blocos  ...       ◯   │
├──────────────────────────────────────┬───────────────────────────────────┤
│ Empresas │ Blocos ativos  OK │ Entradas │ Usuários Online │ Scans Rodando │
│    12    │       38          │   640    │       4         │       1        │
│                                      │ Últimos blocos escaneados          │
│           Distribuição de blocos    │ 203.0.113.0/24             OK       │
│           IP por estado              │ 198.51.100.0/24           Falha     │
│                                      │ Última publicação: v18             │
└──────────────────────────────────────┴───────────────────────────────────┘
```

O botão `OK` da RFC fica dentro do cartão de Blocos ativos. Quando há erro, ele muda para vermelho e abre o detalhe da validação ao ser acionado. Os dois números da coluna direita funcionam como atalhos, respeitando o perfil do usuário.

### Exemplo de Blocos

```text
┌ Blocos ativos ───────────────────────────────────────────────────────────┐
│ Pesquisar bloco ou empresa                         + Novo bloco           │
├──────────────────────────────────────────────────────────────────────────┤
│ [ ] CIDR                 Empresa       ASN       Entradas     Ações        │
│ [ ] 203.0.113.0/24       Empresa A     AS64500   24           Editar       │
│ [ ] 198.51.100.0/24      Empresa B     AS64501   16           Detalhes     │
└──────────────────────────────────────────────────────────────────────────┘
```

A tabela usa `--surface` no corpo, `--surface-2` no cabeçalho e `--border` nos separadores. Isso cria três planos perceptíveis sem depender apenas de cor; o foco continua usando `--border-strong`.

## Alternativa A: Midnight Teal

Mantém o roxo como ação primária e troca os planos neutros por azul petróleo. É uma boa opção se o produto precisar parecer mais orientado a operações e observabilidade.

```css
--bg: #071116;
--surface: #10212A;
--surface-2: #17323B;
--surface-3: #214550;
--border: #3A6570;
--border-strong: #5D9BA0;
--muted: #B9D0D3;
--success: #65E0C2;
```

Na Visão geral, o mapa e os scans ganham uma leitura mais técnica. Em Blocos, os cabeçalhos se destacam como uma camada azul petróleo e o roxo permanece reservado para links e ações.

## Alternativa B: Graphite + Copper

Usa cinza grafite com cobre para alertas e ações de revisão. É indicada para uma marca white label que queira reduzir a associação com roxo sem alterar a estrutura da suíte.

```css
--bg: #101113;
--surface: #1B1D20;
--surface-2: #282B30;
--surface-3: #363A41;
--border: #59616B;
--border-strong: #89939E;
--muted: #C2C7CE;
--success: #71D6A3;
--warning: #F2B66D;
```

Nesta opção, o cobre deve ficar limitado a estados de atenção, revisão e operações destrutivas. O verde continua reservado para disponibilidade e validação aprovada.

As alternativas estão documentadas como tokens para uma futura seleção de tema no white label, sem alterar os templates. O tema aplicado fica como padrão até uma escolha diferente.
