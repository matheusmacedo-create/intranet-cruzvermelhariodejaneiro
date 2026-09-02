# Intranet — Cruz Vermelha Brasileira, Filial do Estado do Rio de Janeiro

Repositório da intranet da CVB-RJ. **Estado atual: fase de escopo.** Nada foi construído ainda. O foco desta etapa é a intranet em si: ambiente de contato entre colaboradores e voluntários, mural por setor, biblioteca de documentos e fluxo de autorização de documentos, construídos sobre uma base pública já consolidada. O que existe aqui é o levantamento, a pesquisa de bases e o escopo, para aprovação antes da construção.

## Documentos

| Documento | O que é | Estado |
| --- | --- | --- |
| [`docs/01-mapa-do-ecossistema.md`](docs/01-mapa-do-ecossistema.md) | O que já existe hoje: Redação, Cérebro, Curso de Punção Venosa/Secretaria, site institucional, Google Workspace, contas e limites, dores observadas | pronto |
| [`docs/02-escopo.md`](docs/02-escopo.md) | O escopo da intranet, documento de aprovação da Diretoria: os quatro espaços (contato, mural por setor, biblioteca, autorização de documentos), identidade e permissões, arquitetura e operação, fases, custos, riscos, critérios de aceite e 48 decisões pendentes | pronto |
| [`docs/03-bases-recomendadas.md`](docs/03-bases-recomendadas.md) | Pesquisa de bases públicas consolidadas (82 candidatos, 50 com ficha técnica: projetos do Movimento Cruz Vermelha, intranets open source, gestão documental e assinatura, referências brasileiras e legais) e a recomendação verificada de em qual construir | pronto |
| [`docs/04-rastreabilidade-blockchain.md`](docs/04-rastreabilidade-blockchain.md) | Existe projeto público de intranet rastreada por blockchain? O que existe de consolidado, precedentes do Movimento, validade jurídica no Brasil, LGPD e o desenho progressivo de rastreabilidade sobre o Supabase | pronto |

### Anexos

| Anexo | O que é |
| --- | --- |
| [`docs/anexos/02a-modelo-de-dados.sql`](docs/anexos/02a-modelo-de-dados.sql) | O modelo de dados proposto: tabelas, enums, funções auxiliares de RLS, policies, grants, triggers e seeds de catálogo |
| [`docs/anexos/02b-testes.sql`](docs/anexos/02b-testes.sql) | Suíte pgTAP que prova os critérios de aceite de cada fase |
| [`docs/anexos/03a-fichas-dos-candidatos.md`](docs/anexos/03a-fichas-dos-candidatos.md) | Ficha técnica dos 50 candidatos avaliados: notas por critério, licença conferida, o que reaproveitar, o que não serve, veredito |
| [`docs/anexos/03b-julgamentos.md`](docs/anexos/03b-julgamentos.md) | Os três julgamentos independentes (direção da filial, arquitetura e manutenção, coordenação de voluntariado): ranking, estratégia, descartes e lacunas |
| [`docs/anexos/03c-verificacao.md`](docs/anexos/03c-verificacao.md) | Refutação adversarial da primeira versão da recomendação (capacidade, operação, adoção e instituição) e o que mudou na revisão |
| [`docs/anexos/03d-estudos-casos-e-normas.md`](docs/anexos/03d-estudos-casos-e-normas.md) | Casos de intranets e portais de Sociedades Nacionais, guias da IFRC, normas brasileiras e estudos sobre intranets consultados |

## Sistemas irmãos

- [redacao-cruzvermelhariodejaneiro](https://github.com/matheusmacedo-create/redacao-cruzvermelhariodejaneiro) — sistema editorial (pautas, aprovações, publicação, newsletter)
- [cerebrocruzvermelha](https://github.com/matheusmacedo-create/cerebrocruzvermelha) — monitoramento e triagem de sinais
- [puncaovenosa-fullautomatic](https://github.com/matheusmacedo-create/puncaovenosa-fullautomatic) — funil do curso e painel da Secretaria

## Convenções herdadas

Next.js 16, React 19, TypeScript, Tailwind 4, Base UI, pnpm, Vercel e Supabase com RLS em tudo. Interface, código novo, commits e documentação em português; status em inglês no banco. Detalhes em `docs/01-mapa-do-ecossistema.md`, seção 5.
