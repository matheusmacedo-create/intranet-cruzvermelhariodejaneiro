# Intranet — Cruz Vermelha Brasileira, Filial do Estado do Rio de Janeiro

Repositório da intranet da CVB-RJ. **Estado atual: fase de escopo.** Nada foi construído ainda. O foco desta etapa é a intranet em si: ambiente de contato entre colaboradores e voluntários, mural por setor, biblioteca de documentos e fluxo de autorização de documentos, construídos sobre uma base pública já consolidada. O que existe aqui é o levantamento, a pesquisa de bases e o escopo, para aprovação antes da construção.

## Documentos

| Documento | O que é | Estado |
| --- | --- | --- |
| [`docs/01-mapa-do-ecossistema.md`](docs/01-mapa-do-ecossistema.md) | O que já existe hoje: Redação, Cérebro, Curso de Punção Venosa/Secretaria, site institucional, Google Workspace, contas e limites, dores observadas | pronto |
| `docs/02-escopo.md` | O escopo da intranet: contato entre colaboradores e voluntários, mural por setor, biblioteca de documentos e fluxo de autorização de documentos, construído sobre a base recomendada | em elaboração |
| `docs/03-bases-recomendadas.md` | Pesquisa de bases públicas consolidadas (projetos do Movimento Cruz Vermelha, intranets open source, gestão documental, referências brasileiras) e a recomendação de em qual construir | em elaboração |
| [`docs/04-rastreabilidade-blockchain.md`](docs/04-rastreabilidade-blockchain.md) | Existe projeto público de intranet rastreada por blockchain? O que existe de consolidado, precedentes do Movimento, validade jurídica no Brasil, LGPD e o desenho progressivo de rastreabilidade sobre o Supabase | pronto |

## Sistemas irmãos

- [redacao-cruzvermelhariodejaneiro](https://github.com/matheusmacedo-create/redacao-cruzvermelhariodejaneiro) — sistema editorial (pautas, aprovações, publicação, newsletter)
- [cerebrocruzvermelha](https://github.com/matheusmacedo-create/cerebrocruzvermelha) — monitoramento e triagem de sinais
- [puncaovenosa-fullautomatic](https://github.com/matheusmacedo-create/puncaovenosa-fullautomatic) — funil do curso e painel da Secretaria

## Convenções herdadas

Next.js 16, React 19, TypeScript, Tailwind 4, Base UI, pnpm, Vercel e Supabase com RLS em tudo. Interface, código novo, commits e documentação em português; status em inglês no banco. Detalhes em `docs/01-mapa-do-ecossistema.md`, seção 5.
