# Mapa do ecossistema atual — Cruz Vermelha Brasileira, Filial do Estado do Rio de Janeiro

Levantado em 01/09/2026 a partir dos repositórios do GitHub, dos projetos Supabase, dos e-mails de serviço e das notificações da Vercel. Serve de base para o escopo da intranet.

## 1. A instituição

- **Razão social:** Cruz Vermelha Brasileira — Filial do Estado do Rio de Janeiro (CNPJ 08.560.973/0001-97). Também existe uma filial municipal (Itaguaí) com CNPJ próprio.
- **Domínio institucional:** `cruzvermelhariodejaneiro.org` (site na Hostinger; e-mail no Google Workspace Business Starter, conta `contato@`). O Workspace está com **94% do armazenamento em pool** e com **falha recorrente no pagamento** da assinatura (e-mails de julho/agosto).
- **Coordenações reconhecidas pelos sistemas atuais:** Comunicação, Humanitário, GRD (Gestão de Risco e Desastres), Saúde, Voluntariado, Primeiros Socorros, Diretoria.
- **Eixos temáticos (Cérebro):** GRD, Saúde, Primeiros socorros, Voluntariado, Institucional.
- **Vínculos com o Movimento:** CVB nacional, outras filiais (SP, MG), IFRC, CICV — todos monitorados como fontes.
- **Pessoas que aparecem nos sistemas:** equipe, voluntários, especialistas, entrevistados, parceiros (categorias do cadastro de Pessoas da Redação). Hoje há 4 perfis cadastrados na Redação.
- **Quem opera a tecnologia:** Matheus Macedo (matheus.macedo@unicopag.com), da ÚnicoPag, que também é o provedor de pagamentos usado pelo curso. Equipe técnica muito pequena; construção fortemente assistida por agentes (v0, Claude Code).

## 2. Sistemas que já existem

### 2.1 Redação — sistema editorial interno
- **URL:** `redacao.cruzvermelhariodejaneiro.org` (Vercel, projeto `redacao-cruzvermelhariodejaneiro`). Deploys de produção falharam em 30/08 e 01/09 (e-mails da Vercel).
- **Repo:** `matheusmacedo-create/redacao-cruzvermelhariodejaneiro` (274 arquivos, 122+ PRs, último commit 01/09/2026). Nasceu no v0.
- **Stack:** Next.js 16 (App Router, Turbopack), React 19, TypeScript, Tailwind 4 + Base UI (padrão shadcn), lucide-react, **pnpm**. Server Actions para toda escrita; rotas `/api` só quando precisa de HTTP (upload, download, diagnósticos, webhooks). Middleware chama-se `proxy.ts`.
- **Banco:** Supabase `RedacaoCruzVermelha-Rj` (ref `wlbbfkudeibalkaqphpo`, região **ca-central-1**, Postgres 17). 22 tabelas, RLS em todas: `workspaces, workspace_members, profiles, projects, pautas, pauta_participants, pauta_links, content_pieces, content_versions, content_comments, approvals, approval_voters, calendar_events, inbox_items, messages, files, notifications, activity_log, social_publications, social_packages, package_destinations, newsletter_inscritos`. Funções RLS auxiliares no schema `private`; RPCs `submit_pauta_for_approval`, `submit_content_for_approval`, `vote_on_approval` (security invoker). Nenhuma Edge Function.
- **Autenticação e papéis:** Supabase Auth com **usuários internos sintéticos** (`usuario@usuarios.cvrj.local`, login por nome de usuário + senha). Papéis: `admin`, `editor`, `colaborador` em `workspace_members.role`. Estrutura multi-espaço existe no banco, mas o app opera em **espaço único** (`production`). Bootstrap cria o primeiro admin quando o banco está vazio.
- **Navegação atual (sidebar):** Visão geral (dashboard) · Trabalho: Cérebro, Pautas, Projetos, Publicações (hub de pacotes), Central de e-mail (newsletter), Calendário, Biblioteca · Operação: Aprovações, Caixa de entrada · Análise: Impacto, Registro · Equipe: Mensagens, Pessoas · Configurações, Perfil. Há ainda `/registrar` (formulário de registro de Ação/Evento/História/Ideia/Material/Sugestão/Outro) e `/conteudos/[id]` (editor).
- **Fluxo modelado:** registrar o que aconteceu → pauta → conteúdo → aprovação (votação de participantes, ninguém aprova o próprio texto) → publicação (redes via Upload-Post; site via FTP; newsletter via Resend).
- **Biblioteca de arquivos:** Vercel Blob privado, upload direto do navegador (limite serverless 4,5 MB), teto 300 MB/arquivo e 1 GB/espaço; cada arquivo tem `authorization_status` (direito de uso de imagem: `authorized` publica, `pending`, `internal`).
- **Hub de publicações:** pacote mestre (formato matéria: título, subtítulo, corpo, slug, legendas/créditos por mídia) + destinos por canal (adapters para site-web, instagram, facebook, linkedin, x, threads, bluesky, mastodon, pinterest, reddit, google-business, telegram, discord, tiktok, youtube, newsletter). Registro de publicações (`package_destinations.publicado_em`) e painel de Impacto (últimos 30 dias, por canal).
- **Newsletter:** inscritos com dupla confirmação e registro de consentimento LGPD; envio pelo Resend com remetente `noticias@noticias.cruzvermelhariodejaneiro.org`; formulário da home do site; exportação CSV.
- **IA:** OpenAI (imagem por rede, legenda) e Anthropic (melhorar matéria), com teto mensal de imagens e rotas de diagnóstico.
- **Integrações:** Upload-Post (plano gratuito: 2 perfis, 10 publicações/mês; a conta Facebook vinculada administra 22 páginas — `UPLOAD_POST_FACEBOOK_PAGE_ID` obrigatória), FTPS Hostinger (publicação no site em `/noticias`, **fluxo incompleto**), Resend, Cérebro (leitura de `/api/pauta`, importação para o hub, devolução de recusas e `GET /api/cerebro/contexto`).
- **Convenções:** interface e código novo em português; status gravados em inglês no banco e traduzidos em `lib/status-maps.ts`; toda action começa com `requireWorkspace()`/`requireAdmin()` e filtra por `workspace_id`; lógica não trivial em módulos puros em `lib/`; **sem suíte de testes** (só `tsc --noEmit` e `pnpm build`); `pnpm lint` quebrado; migrações só acrescentam (coluna só sai depois do deploy que parou de usá-la); credenciais nunca em chat/código.
- **Pendências declaradas:** gerador de HTML e publicação no site (pasta FTP errada), migração de limpeza de `file_id`, `eslint.config.js`, testes, decisão sobre plano pago do Upload-Post.

### 2.2 Cérebro de Notícias — monitoramento e triagem
- **URL:** `cerebrocruzvermelha.vercel.app` (Vercel, projeto `cerebro-cruz-vermelha`, região `gru1` só valeria no plano Pro).
- **Repo:** `matheusmacedo-create/cerebrocruzvermelha` (62 arquivos, PR #4 em 01/09/2026).
- **Stack:** Next.js 16, React 19, TypeScript, npm. **Sem banco próprio**: a Apify é coleta e armazenamento (Dataset por run, Key-Value Store com o snapshot `acervo-atual`); acervo semente no repo (263 sinais).
- **O que faz:** observa lista fechada de 26 contas (Instagram e X) + RSS/APIs/diários oficiais, em 4 cadências agendadas na Apify (webhook `ACTOR.RUN.SUCCEEDED` avisa o app). Pontua cada sinal por 6 perguntas (local? urgente? relação conosco? ação real? já falamos? fonte confiável?) com travas duras (só mídia `autorizado` publica; fontes de uso interno — Fogo Cruzado, OTT, mobilidade — nunca viram conteúdo público). Decide entre agir agora / produzir / agendar / avaliar / monitorar / arquivar. Regras + léxico, sem modelo generativo (auditável e barato). **Não publica.**
- **Telas:** Hoje, Jornal, Acervo, Calendário, Fontes. Rotas: `/api/pauta` (contrato versionado 1.0), `/api/feedback`, `/api/grafo`, `/api/midia/[id]`, `/api/saude`, `/api/coleta`, `/api/webhook/apify`.
- **Fontes por categoria:** emergência (COR-Rio, Alerta Rio, Defesa Civil municipal e estadual, CBMERJ, INEA), saúde (SMS-Rio, SES-RJ, Hemorio, Fiocruz), território (Voz das Comunidades, Maré de Notícias, Fala Roça, Agência Lume, LabJaca), segurança (Fogo Cruzado, OTT — uso interno), mobilidade (MetrôRio, SuperVia, CCR Barcas), movimento (CVB RJ, nacional, MG, SP, IFRC, CICV).
- **Custo medido:** US$ 0,0023 por post coletado. Fase 2 pendente: X/Twitter, sites que bloqueiam scraping (DOU, IOERJ, Prefeitura).

### 2.3 Curso de Punção Venosa — funil de venda, matrícula e Secretaria
- **URL:** `cursoscruzvermelha.org` (e-mails saem de `noreply@cursoscruzvermelha.org`, assunto "Secretaria CVB-RJ").
- **Repo:** `matheusmacedo-create/puncaovenosa-fullautomatic` (192 arquivos, PR #39 em 25/08/2026).
- **Stack:** Next.js 16, React 19, TypeScript strict, Tailwind 4, Base UI, pnpm, `qrcode`, `leaflet`, Vercel Analytics. Todo acesso ao banco por route handlers com a chave secreta; RLS forçada sem policies.
- **Banco:** Supabase `puncaovenosa-fullautomatic` (ref `lqpnbqislaxzhqkszijg`, região **sa-east-1**). Tabelas: `inscricoes` (CPF como chave natural), `triagem_respostas`, `pagamentos` (PIX e cartão, itens com constraint de soma), `validacoes`, `webhook_entregas`, `meta_capi_entregas`, `visitas_landing`, `meta_publico_membros`; 13 migrations. RPCs `upsert_inscricao`, `confirmar_pagamento` (idempotente), `concluir_triagem_se_completa`, `funil_por_origem`.
- **Fluxo:** landing (`/` e `/lp/[slug]`, testes A/B por link, UTMs com atribuição de primeiro toque) → dados → pagamento (PIX/cartão via **Únicopag**, postback verificado por consulta à API) → confirmação → triagem de 8 passos (CEP via BrasilAPI/ViaCEP) → ficha do aluno PWA com QR → `/validar/[token]` na portaria, sem login. Preço R$ 249 (matrícula R$ 99 + curso R$ 150). Páginas legais (privacidade LGPD, reembolso CDC).
- **Painel `/secretaria`:** login por senha (`SECRETARIA_SENHA`) + código por e-mail; alertas de acesso. Blocos: Precisa de atenção · Funil completo · O que converte (por página/campanha) · De onde vêm as inscrições · Checkpoint do webhook · Checkpoint do Pixel (Conversions API) · Checkpoint do público de remarketing. Reenvio manual de webhooks e eventos.
- **Integrações:** Únicopag (pagamentos), Meta Pixel + Conversions API + Marketing API (público de remarketing de abandono, cron diário — limite do plano Hobby), Google Sheets via Apps Script (`PLANILHA_URL`/`PLANILHA_TOKEN`, uma linha por aluno), webhook para a Secretaria (`WEBHOOK_SECRETARIA_URL`), BrasilAPI/ViaCEP.
- **Anúncios:** campanhas ativas no Meta (aprovações de anúncios em agosto).

### 2.4 Site institucional
- `cruzvermelhariodejaneiro.org` na **Hostinger** (HTML estático; FTP em `/home/u448697994/noticias`, fora de `public_html` — motivo de a publicação de notícias da Redação ainda não funcionar). Seção `/noticias` prevista, formulário de newsletter na home ligado à Redação.

### 2.5 Repositórios auxiliares
- `matheusmacedo-create/cruzvermelhariodejaneiro` — vazio (só `.gitkeep`, jul/2026).
- `matheusmacedo-create/intranet-cruzvermelhariodejaneiro` — **este projeto**, vazio (sem commits). Branch de trabalho: `claude/intranet-infrastructure-planning-6pch7c`.

## 3. Contas, serviços e limites
| Serviço | Uso | Situação/limite |
|---|---|---|
| Vercel (time "matheusmacedo-8423's projects", plano **Hobby**) | Redação, Cérebro, Curso | Cron limitado a 1x/dia, `regions` ignorado, body serverless 4,5 MB, deploys de produção da Redação falhando em 30/08 e 01/09 |
| Supabase (org via Vercel) | 2 projetos (Redação em ca-central-1; Curso em sa-east-1) | Regiões diferentes; sem Edge Functions; sem projeto para intranet ainda |
| Vercel Blob | Biblioteca da Redação (privado) | 1 GB por espaço (regra do app) |
| Google Workspace Business Starter | e-mail `@cruzvermelhariodejaneiro.org`, Drive, Planilhas | 94% do armazenamento; pagamento falhando |
| Hostinger | site estático + FTP | conta FTP presa em pasta errada |
| Resend | newsletter | subdomínio `noticias.` verificado; raiz não |
| Upload-Post | publicação em redes | plano gratuito: 2 perfis, 10 posts/mês |
| Apify | coleta do Cérebro | US$ 0,0023/post |
| OpenAI / Anthropic | IA na Redação | chaves dedicadas com teto |
| Únicopag | pagamentos do curso | produção |
| Meta (Pixel, CAPI, Marketing API) | rastreio e remarketing do curso | tokens separados |
| Google Sheets (Apps Script) | espelho de inscrições para a secretaria | planilha restrita |
| ClickUp / Notion | gestão interna da ÚnicoPag; Notion sem token válido | não usados pela CVRJ |

## 4. Dores e lacunas observadas (o que a intranet precisa resolver ou não repetir)
1. **Identidade fragmentada:** Redação usa usuários sintéticos com senha; Secretaria usa senha compartilhada + OTP; Workspace tem contas Google; site e Cérebro não têm login. Não há SSO, nem diretório único de pessoas, nem RBAC comum.
2. **Dados em três lugares:** dois projetos Supabase em regiões diferentes + planilha Google + Apify KV. Sem catálogo, sem backup coordenado.
3. **Comunicação interna informal:** mensagens diretas existem só dentro da Redação; não há mural, avisos, calendário institucional (só editorial), nem documentos/políticas centralizados.
4. **Voluntariado sem sistema:** o cadastro de Pessoas da Redação é editorial (fontes/entrevistados), não um cadastro de voluntários com formação, disponibilidade, escala e horas.
5. **Cursos:** existe um funil para um curso específico; não há catálogo, turmas, presença, certificados, nem histórico do aluno reutilizável.
6. **Emergências/GRD:** o Cérebro detecta sinais, mas não há fluxo de acionamento, escala de plantão, checklist ou registro de operação.
7. **Governança e LGPD:** dados sensíveis (CPF, telefone, saúde) espalhados; sem política de retenção, sem trilha de auditoria unificada (só `activity_log` da Redação).
8. **Operação de plataforma:** planos gratuitos/Hobby em tudo; Workspace com pagamento falhando e disco cheio; sem monitoramento, sem testes, deploys quebrando.
9. **Conhecimento:** documentação técnica excelente dentro dos repos, mas nada institucional (manuais, procedimentos, organograma, contatos).

## 5. Convenções que o novo projeto deve herdar
- Next.js 16 + React 19 + TypeScript + Tailwind 4 + Base UI/shadcn + lucide-react; **pnpm**; Vercel; Supabase com RLS em tudo; Server Actions para escrita; `proxy.ts` como middleware.
- Interface, código novo, commits e documentação em **português**; status em inglês no banco.
- Toda página/ação começa com `requireSession()/requireWorkspace()/requireAdmin()`; nunca confiar na tela.
- Migrações só acrescentam; credenciais só por nome; rotas de diagnóstico que só leem; documentação de "armadilhas pagas" (ARQUITETURA.md) como prática.
- Lógica pura fora das actions, conferível por script; `tsc --noEmit` + `pnpm build` antes de todo push.
