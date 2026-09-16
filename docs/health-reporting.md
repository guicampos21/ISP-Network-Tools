# Relatórios do ISP Network Health

Os relatórios finais mostram uma linha por endereço IP. A tela apresenta o alvo, o risco, a quantidade de endereços IP verificados, as sub-redes `/24`, as blacklists únicas consultadas e o tempo total entre o início e o encerramento da análise.

Os resultados são organizados por bloco. Cada IP exibe inicialmente apenas as blacklists que detectaram uma ocorrência; quando não há detecção, aparece o estado **Limpo**. O conjunto da coluna pode ser focalizado ou receber o ponteiro do mouse para mostrar a lista completa de fontes consultadas. Vermelho significa detecção, verde significa consulta concluída sem detecção e amarelo significa consulta incompleta.

Use **Expandir todos** para abrir os blocos da tela e **Recolher todos** para voltar à leitura resumida. A coluna de resposta DNS e o tempo de cada consulta não fazem parte da visão executiva: uma resposta vazia era ambígua e o tempo individual não representa o tempo total da análise.

Use **Gerar PDF** para obter o documento produzido pelo servidor. O PDF segue uma decisão automática: análises maiores são separadas por blocos `/24`; blocos limpos permanecem recolhidos e blocos com qualquer detecção são expandidos com os IPs envolvidos. Para um `/24` ou bloco menor, o documento mostra somente o bloco escaneado e aplica a mesma regra de expansão. Não há um controle no navegador para alterar essa decisão.
