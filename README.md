# Intranet — Cruz Vermelha Brasileira, Filial do Estado do Rio de Janeiro

Repositório da intranet da CVB-RJ. **Estado atual: fase de escopo.** Nada foi construído ainda; o que existe aqui é o levantamento do ecossistema e o escopo completo do projeto, para aprovação antes da construção.

## Documentos

| Documento | O que é |
| --- | --- |
| [`docs/01-mapa-do-ecossistema.md`](docs/01-mapa-do-ecossistema.md) | O que já existe hoje: Redação, Cérebro, Curso de Punção Venosa/Secretaria, site institucional, Google Workspace, contas e limites, dores observadas |
| [`docs/02-escopo.md`](docs/02-escopo.md) | O escopo mestre da intranet: perfis, mapa de espaços, arquitetura e infraestrutura, integrações, fases, riscos, critérios de aceite e decisões pendentes |
| [`docs/anexos/`](docs/anexos/) | As seis propostas independentes que alimentaram a síntese e o julgamento do painel |

## Sistemas irmãos

- [redacao-cruzvermelhariodejaneiro](https://github.com/matheusmacedo-create/redacao-cruzvermelhariodejaneiro) — sistema editorial (pautas, aprovações, publicação, newsletter)
- [cerebrocruzvermelha](https://github.com/matheusmacedo-create/cerebrocruzvermelha) — monitoramento e triagem de sinais
- [puncaovenosa-fullautomatic](https://github.com/matheusmacedo-create/puncaovenosa-fullautomatic) — funil do curso e painel da Secretaria

## Convenções herdadas

Next.js 16, React 19, TypeScript, Tailwind 4, Base UI, pnpm, Vercel e Supabase com RLS em tudo. Interface, código novo, commits e documentação em português; status em inglês no banco. Detalhes em `docs/01-mapa-do-ecossistema.md`, seção 5.
