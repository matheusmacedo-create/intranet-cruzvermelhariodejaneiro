-- Suite de testes da intranet da CVB-RJ
-- Anexo 02b do escopo (docs/02-escopo.md). pgTAP sobre o anexo 02a.
--
-- O QUE ISTO E
-- Os criterios de aceite da secao 17 do escopo, escritos como teste executavel.
-- No repositorio da intranet cada bloco vira um arquivo em supabase/tests/ e roda
-- por supabase test db na integracao continua, como condicao de aceite de cada fase.
--
-- COMO RODAR
--   create extension if not exists pgtap;
--   psql -f 02b-testes.sql
-- Cada bloco e uma transacao com rollback ao fim: a suite nao deixa residuo e pode
-- rodar contra um banco com dados.
--
-- ESTADO CONFERIDO
-- 508 testes, todos verdes, contra o anexo 02a aplicado do zero sobre as 21
-- migrations da Redacao, em Postgres 16 com um ambiente que imita o Supabase.
--   identidade, setores, papeis e permissoes ..... 205
--   contato e mural por setor .....................118
--   biblioteca de documentos ...................... 92
--   autorizacao, assinatura e trilha .............. 93
--
-- O QUE ESTA SUITE JA ENCONTROU
-- Escrever os testes revelou onze defeitos que a leitura do codigo nao tinha pego,
-- todos corrigidos no anexo 02a antes desta versao. Os mais graves: documento
-- sigiloso ficava inacessivel para sempre, porque ninguem conseguia conceder a
-- primeira credencial; nenhuma sessao conseguia alterar aviso nenhum, por recursao
-- infinita na policy de moderacao; a trilha recusava gravacao de usuario comum, o
-- que travava o tramite inteiro das fases 4 e 5; e nenhum pedido de autorizacao
-- conseguia nascer. Cada correcao tem comment on no 02a citando o numero do teste.
--
-- LIMITE HONESTO
-- O ambiente de conferencia e Postgres 16, nao 17, e repoe a mao dois grants que o
-- Supabase de verdade ja tem (usage nos schemas auth e extensions para
-- authenticated). Onde a suite repoe algo assim, o comentario diz que aquilo nao
-- faz parte do que esta sob teste.


-- ============================================================
-- 01. Identidade, setores, papeis, permissoes, vinculos, convites e consentimentos
-- ============================================================

-- ===========================================================================
-- Testes pgTAP da intranet da CVB-RJ, fase 0 e fase 1.
-- Area: identidade, setores, papeis, permissoes, vinculos, convites e
-- consentimentos. Seções 5, 6 e 17 do escopo.
--
-- Como rodar:
--   /pgtest/novo_banco.sh t_identidade
--   psql -h /pgtest/sock -U postgres -d t_identidade -f testes-01-identidade.sql
--
-- Tudo roda dentro de uma transação que termina em rollback: o banco volta ao
-- estado anterior, inclusive as concessões de privilégio feitas logo abaixo.
-- ===========================================================================

begin;

-- ---------------------------------------------------------------------------
-- Preparo do ambiente, não do modelo.
--
-- O Supabase concede, por default privileges do projeto, o uso do schema auth
-- e a leitura de public.profiles ao papel authenticated. Este cluster de teste
-- imita o Supabase mas não reproduz essas concessões, e sem elas nenhuma
-- consulta feita como authenticated chegaria a rodar. As duas linhas abaixo
-- repõem só isso e somem no rollback.
-- ---------------------------------------------------------------------------
grant usage on schema auth to authenticated, anon;
grant select on table public.profiles to authenticated;

select plan(205);


-- ===========================================================================
-- 1. Estrutura: as tabelas que a identidade exige
-- ===========================================================================

select has_table('public', 'profiles',            'A pessoa tem um perfil');
select has_table('public', 'profiles_restritos',  'O dado pessoal restrito mora em tabela separada do perfil aberto');
select has_table('public', 'setores',             'A filial se organiza em setores');
select has_table('public', 'vinculos',            'A relação da pessoa com a filial é um vínculo com história');
select has_table('public', 'papeis',              'Papel é linha de tabela, para entrar papel novo sem mexer em tipo');
select has_table('public', 'papel_permissoes',    'Cada papel carrega a lista das permissões que exerce');
select has_table('public', 'usuario_papeis',      'A atribuição de papel a uma pessoa é registrada com vigência');
select has_table('public', 'delegacoes',          'A ausência de quem decide é registrada como delegação');
select has_table('public', 'convites',            'Quem não é da casa só entra por convite registrado');
select has_table('public', 'consentimentos',      'O consentimento do titular é registrado e guardado');
select has_table('public', 'codigos_recuperacao', 'Quem perde o aparelho do segundo fator tem código de recuperação');
select has_table('public', 'termos_adesao',       'O termo de adesão assinado é registrado');

select has_enum('public', 'permissao', 'Permissão é tipo enumerado de verdade, porque atravessa muitas tabelas');
select hasnt_type('public', 'papel',  'Papel não é tipo enumerado: papel novo entra por linha, não por alteração de tipo');

select col_is_pk('public', 'profiles_restritos', 'profile_id',
  'O cadastro restrito é um para um com o perfil: no máximo uma linha por pessoa');

select fk_ok('public', 'profiles_restritos', 'profile_id', 'public', 'profiles', 'id',
  'O cadastro restrito aponta para a pessoa a quem pertence');
select fk_ok('public', 'vinculos', 'profile_id', 'public', 'profiles', 'id',
  'Todo vínculo é de uma pessoa que existe');
select fk_ok('public', 'vinculos', 'setor_id', 'public', 'setores', 'id',
  'O setor do vínculo é um setor que existe');
select fk_ok('public', 'usuario_papeis', 'papel', 'public', 'papeis', 'slug',
  'Só se concede papel que está no catálogo de papéis');
select fk_ok('public', 'papel_permissoes', 'papel', 'public', 'papeis', 'slug',
  'Só se dá permissão a papel que está no catálogo de papéis');
select fk_ok('public', 'convites', 'papel_inicial', 'public', 'papeis', 'slug',
  'O papel prometido no convite é um papel que existe');
select fk_ok('public', 'delegacoes', 'delegado_id', 'public', 'profiles', 'id',
  'Quem recebe a delegação é uma pessoa que existe');

select has_column('public', 'profiles', 'tipo_conta',
  'O perfil diz por qual porta a pessoa entrou: equipe, voluntário ou externo');
select has_column('public', 'profiles', 'acesso_expira_em',
  'O convidado com prazo tem data para o acesso acabar');
select has_column('public', 'profiles', 'visibilidade_diretorio',
  'A pessoa escolhe quem a enxerga no diretório');
select has_column('public', 'profiles', 'mfa_verificado_em',
  'O perfil guarda o espelho de leitura da última verificação de segundo fator');

select has_column('public', 'vinculos', 'estado',
  'O vínculo tem estado, no ciclo de vida do voluntário da IFRC');
select has_column('public', 'vinculos', 'fim',
  'O vínculo tem fim, porque a relação com a filial acaba');
select has_column('public', 'vinculos', 'motivo_termino',
  'Quando o vínculo acaba, fica registrado o motivo');
select has_column('public', 'vinculos', 'anterior_id',
  'Transferência e promoção apontam para o vínculo anterior, em vez de apagá-lo');
select has_column('public', 'vinculos', 'confirmado_por',
  'Fica registrado quem confirmou o vínculo');
select has_column('public', 'vinculos', 'confirmado_em',
  'Fica registrado quando o vínculo foi confirmado');

select has_column('public', 'usuario_papeis', 'setor_id',
  'A concessão de papel pode ser presa a um setor');
select has_column('public', 'usuario_papeis', 'fim',
  'A concessão de papel tem vigência e termina');
select has_column('public', 'usuario_papeis', 'concedido_por',
  'Fica registrado quem concedeu o papel');

select has_column('public', 'papeis', 'escopo',
  'O papel diz se vale na filial inteira ou só dentro de um setor');
select has_column('public', 'papeis', 'exige_mfa',
  'O papel diz se exige segundo fator');
select has_column('public', 'papeis', 'somente_leitura',
  'O papel diz se é papel que só lê');
select has_column('public', 'papeis', 'alcance',
  'O papel tem ordem de alcance, para escolher o papel principal de quem tem vários');

select has_column('public', 'convites', 'token_hash',
  'O convite guarda o resumo do código, nunca o código em claro');
select has_column('public', 'convites', 'expira_em',
  'O convite tem prazo de validade');
select has_column('public', 'convites', 'aceito_em',
  'O convite registra quando foi aceito');
select has_column('public', 'convites', 'revogado_em',
  'O convite registra quando foi revogado');

select has_function('private', 'pertence_ao_espaco', array['uuid'],
  'Existe a função que responde se a pessoa pertence ao espaço');
select has_function('private', 'pertence_ao_setor', array['uuid'],
  'Existe a função que responde se a pessoa pertence ao setor');
select has_function('private', 'alcance_do_diretorio', array[]::text[],
  'Existe a função que diz até onde a pessoa enxerga o diretório');
select has_function('private', 'exige_aal2', array[]::text[],
  'Existe a função que exige sessão com segundo fator');
select has_function('public', 'autorizar', array['permissao', 'uuid'],
  'Existe a função única de autorização, que recebe permissão e setor');

select ok(
  (select count(*) from pg_indexes
    where schemaname = 'public' and indexname = 'vinculos_vigente_idx') = 1,
  'Há índice único garantindo um vínculo em aberto por pessoa, setor e tipo');
select ok(
  (select count(*) from pg_indexes
    where schemaname = 'public' and indexname = 'consentimentos_vigente_idx') = 1,
  'Há índice único garantindo um consentimento vigente por pessoa e finalidade');
select ok(
  (select count(*) from pg_indexes
    where schemaname = 'public' and indexname = 'convites_token_hash_idx') = 1,
  'O resumo do código do convite é único, para que um código valha por um convite só');
select ok(
  (select count(*) from pg_indexes
    where schemaname = 'public' and indexname = 'usuario_papeis_vigente_idx') = 1,
  'Há índice único impedindo conceder duas vezes o mesmo papel no mesmo setor à mesma pessoa');

-- O escopo promete a lista de permissões da seção 5.3 e promete que decisão é
-- sempre autorizacao ponto alguma coisa. Estes dois testes prendem o texto ao
-- catálogo, como manda a seção 17.1.
select is_empty($$
  select nome from unnest(array[
    'pessoa.convidar','pessoa.confirmar_vinculo','pessoa.ver_restrito','pessoa.editar_restrito',
    'papel.conceder','papel.revogar','delegacao.criar','mural.publicar','mural.aprovar',
    'mural.moderar','mural.ver_relatorio','documento.enviar','documento.versionar',
    'documento.classificar','documento.permissionar','documento.eliminar','autorizacao.abrir',
    'autorizacao.aprovar','autorizacao.homologar','autorizacao.assinar','autorizacao.regrar',
    'trilha.ler_completa','lgpd.responder_titular','operacao.administrar'
  ]) as nome
  where nome not in (select unnest(enum_range(null::public.permissao))::text)
$$, 'Toda permissão que o escopo cita pelo nome existe mesmo no catálogo');

select is_empty($$
  select nome from unnest(array['documento.aprovar','documento.homologar','documento.assinar']) as nome
  where nome in (select unnest(enum_range(null::public.permissao))::text)
$$, 'Decisão é sempre autorização: aprovar, homologar e assinar documento não existem como permissão');

select is_empty($$
  select p.proname from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'private'
  group by p.proname having count(*) > 1
$$, 'Nenhuma função auxiliar de apoio está definida duas vezes');

select is_empty($$
  select 'telefone' where (
    select pg_get_expr(a.attgenerated_expr, a.attrelid) from (
      select d.adbin as attgenerated_expr, d.adrelid as attrelid
      from pg_attrdef d
      join pg_attribute at on at.attrelid = d.adrelid and at.attnum = d.adnum
      where d.adrelid = 'public.profiles'::regclass and at.attname = 'busca'
    ) a
  ) ilike '%telefone%'
$$, 'O telefone não entra no índice de busca do diretório');


-- ===========================================================================
-- 2. Segurança em nível de linha e concessões
-- ===========================================================================

-- Este é o teste que reprova se alguma tabela da identidade ficar sem RLS.
select is_empty($$
  select c.relname
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r'
    and c.relname = any (array['profiles','profiles_restritos','setores','vinculos','papeis',
                               'papel_permissoes','usuario_papeis','delegacoes','convites',
                               'consentimentos','codigos_recuperacao','termos_adesao',
                               'formacoes','credenciais','hipoteses_legais'])
    and not c.relrowsecurity
$$, 'Nenhuma tabela da identidade fica sem segurança em nível de linha ligada');

select is_empty($$
  select c.relname
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r'
    and c.relname = any (array['profiles','profiles_restritos','setores','vinculos','papeis',
                               'papel_permissoes','usuario_papeis','delegacoes','convites',
                               'consentimentos','codigos_recuperacao','termos_adesao',
                               'formacoes','credenciais','hipoteses_legais'])
    and has_table_privilege('authenticated', c.oid, 'select')
    and not exists (select 1 from pg_policies p
                     where p.schemaname = 'public' and p.tablename = c.relname)
$$, 'Toda tabela da identidade que a pessoa logada alcança tem ao menos uma policy');

select ok((select count(*) from pg_policies where schemaname='public' and tablename='vinculos') >= 3,
  'O vínculo tem policy para ler, para criar e para alterar');
select ok((select count(*) from pg_policies where schemaname='public' and tablename='profiles_restritos') >= 3,
  'O cadastro restrito tem policy para ler, para criar e para alterar');
select ok((select count(*) from pg_policies where schemaname='public' and tablename='consentimentos') >= 3,
  'O consentimento tem policy para ler, para criar e para alterar');

select ok(not has_table_privilege('anon', 'public.convites', 'select'),
  'Quem não entrou não lê a tabela de convites');
select ok(not has_function_privilege('anon', 'public.consultar_convite(text)', 'execute'),
  'Quem não entrou nem consulta convite pela função de retorno fixo');
select ok(not has_table_privilege('authenticated', 'public.codigos_recuperacao', 'select'),
  'Ninguém lê a tabela de códigos de recuperação direto: só a função confere o código');

-- As colunas de segurança do perfil não são graváveis pela própria pessoa.
select is_empty($$
  select coluna from unnest(array['mfa_verificado_em','tipo_conta','setor_principal_id',
                                  'acesso_expira_em','desativado_em','eliminado_em']) as coluna
  where has_column_privilege('authenticated', 'public.profiles', coluna, 'update')
$$, 'A própria pessoa não grava as colunas de segurança do seu perfil');

select ok(has_column_privilege('authenticated', 'public.profiles', 'apresentacao', 'update'),
  'A própria pessoa continua podendo editar a sua apresentação');
select ok(has_column_privilege('authenticated', 'public.profiles', 'visibilidade_diretorio', 'update'),
  'A própria pessoa continua podendo escolher quem a enxerga no diretório');


-- ===========================================================================
-- 3. Cenário: as pessoas da filial
-- ===========================================================================

-- Quem entra pelo domínio da casa nasce com perfil de equipe e vínculo novo,
-- pelo gatilho de novo usuário. Quem entra de fora, sem convite, não nasce
-- com vínculo nenhum e será mandado para a tela de sem vínculo.
insert into auth.users (id, email) values
  ('aaaa0001-0000-4000-8000-000000000001', 'sonia@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000002', 'carla@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000003', 'clara@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000007', 'alice@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000009', 'ester@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000010', 'bento@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000011', 'bianca@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000012', 'teodoro@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000013', 'heloisa@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000014', 'dora@cruzvermelhariodejaneiro.org'),
  ('aaaa0001-0000-4000-8000-000000000004', 'vitor@voluntario.org.br'),
  ('aaaa0001-0000-4000-8000-000000000005', 'nilza@voluntario.org.br'),
  ('aaaa0001-0000-4000-8000-000000000006', 'sergio@forasteiro.org'),
  ('aaaa0001-0000-4000-8000-000000000008', 'paulo@parceira.com.br'),
  ('aaaa0001-0000-4000-8000-000000000015', 'flavia@outroespaco.org'),
  ('aaaa0001-0000-4000-8000-000000000016', 'robo@integracao.local');

select is(
  (select tipo_conta from public.profiles where id = 'aaaa0001-0000-4000-8000-000000000002'),
  'equipe',
  'Quem chega com e-mail do domínio da casa nasce como equipe');
select is(
  (select estado from public.vinculos where profile_id = 'aaaa0001-0000-4000-8000-000000000002'),
  'new',
  'Quem chega pelo domínio da casa nasce com vínculo novo, à espera da Secretaria');
select is(
  (select tipo_conta from public.profiles where id = 'aaaa0001-0000-4000-8000-000000000006'),
  'voluntario',
  'Quem chega de fora nasce como voluntário, não como equipe');
select is(
  (select count(*)::text from public.vinculos where profile_id = 'aaaa0001-0000-4000-8000-000000000006'),
  '0',
  'Quem chega de fora sem convite não ganha vínculo nenhum');
select is(
  (select count(*)::text from public.usuario_papeis where user_id = 'aaaa0001-0000-4000-8000-000000000002'),
  '0',
  'Quem chega pelo domínio da casa não ganha papel nenhum de brinde');
select is(
  (select username from public.profiles where id = 'aaaa0001-0000-4000-8000-000000000013'),
  'heloisa',
  'O nome de usuário vem da parte local do e-mail');

-- Um segundo espaço, para provar que perfil de um espaço não vaza no outro.
insert into public.workspaces (id, name, slug, kind)
values ('bbbb0001-0000-4000-8000-000000000001', 'Homologação', 'homologacao', 'demo');

-- Os identificadores do espaço e dos setores ficam em tabelas temporárias legíveis
-- por quem está logado. Assim as consultas feitas como pessoa logada não dependem
-- de ler public.workspaces, que é tabela da Redação e tem regra própria.
create temporary table espaco on commit drop as
  select id from public.workspaces where kind = 'production';
create temporary table setor on commit drop as
  select slug, id from public.setores;
grant select on espaco, setor to authenticated;

-- Vínculos e papéis do cenário.
update public.vinculos set estado = 'active',
       setor_id = (select id from setor where slug = 'diretoria'),
       confirmado_em = now()
 where profile_id in ('aaaa0001-0000-4000-8000-000000000001',
                      'aaaa0001-0000-4000-8000-000000000007',
                      'aaaa0001-0000-4000-8000-000000000010',
                      'aaaa0001-0000-4000-8000-000000000011',
                      'aaaa0001-0000-4000-8000-000000000012');

update public.vinculos set estado = 'active',
       setor_id = (select id from setor where slug = 'saude'),
       confirmado_em = now()
 where profile_id in ('aaaa0001-0000-4000-8000-000000000002',
                      'aaaa0001-0000-4000-8000-000000000003');

update public.vinculos set estado = 'active',
       setor_id = (select id from setor where slug = 'comunicacao'),
       confirmado_em = now()
 where profile_id = 'aaaa0001-0000-4000-8000-000000000009';

-- Vínculo herdado da relação nominal aprovada pela Diretoria, carregado em lote
-- pela Secretaria, sem formação e sem termo reassinado.
update public.vinculos set estado = 'active', origem = 'carga_inicial',
       setor_id = (select id from setor where slug = 'saude'),
       confirmado_por = 'aaaa0001-0000-4000-8000-000000000001', confirmado_em = now(),
       observacao = 'Relação nominal aprovada pela Diretoria em reunião de 2026-01-20'
 where profile_id = 'aaaa0001-0000-4000-8000-000000000013';

update public.vinculos set estado = 'active', tipo = 'diretoria',
       setor_id = (select id from setor where slug = 'diretoria'),
       confirmado_em = now()
 where profile_id = 'aaaa0001-0000-4000-8000-000000000014';

insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado, confirmado_em)
values
  ((select id from espaco),
   'aaaa0001-0000-4000-8000-000000000004',
   (select id from setor where slug = 'saude'), 'voluntario', 'active', now()),
  ((select id from espaco),
   'aaaa0001-0000-4000-8000-000000000005',
   (select id from setor where slug = 'voluntariado'), 'voluntario', 'new', null),
  ((select id from espaco),
   'aaaa0001-0000-4000-8000-000000000008',
   (select id from setor where slug = 'comunicacao'), 'parceiro_externo', 'active', now()),
  ((select id from espaco),
   'aaaa0001-0000-4000-8000-000000000016', null, 'servico', 'active', now()),
  ('bbbb0001-0000-4000-8000-000000000001',
   'aaaa0001-0000-4000-8000-000000000015', null, 'colaborador', 'active', now());

update public.profiles set tipo_conta = 'servico'
 where id = 'aaaa0001-0000-4000-8000-000000000016';

insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
values
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000001', 'secretaria',       null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000002', 'colaborador',      null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000003', 'coordenador',      (select id from setor where slug = 'saude')),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000004', 'voluntario',       null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000005', 'voluntario',       null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000007', 'auditor',          null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000008', 'parceiro_externo', null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000010', 'administrador',    null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000011', 'administrador',    null),
  ((select id from espaco), 'aaaa0001-0000-4000-8000-000000000014', 'diretoria',        null);

-- Ester é da Redação: tem linha em workspace_members e nenhum papel novo.
insert into public.workspace_members (workspace_id, user_id, role, coordination)
values ((select id from espaco),
        'aaaa0001-0000-4000-8000-000000000009', 'admin', 'comunicacao');

-- Escolhas de visibilidade no diretório.
update public.profiles set visibilidade_diretorio = 'todos'
 where id in ('aaaa0001-0000-4000-8000-000000000002', 'aaaa0001-0000-4000-8000-000000000013');
update public.profiles set visibilidade_diretorio = 'oculto'
 where id = 'aaaa0001-0000-4000-8000-000000000014';

-- Telefone com consentimento vigente, para a regra das três condições.
update public.profiles set telefone = '21999990000', telefone_visivel = true
 where id = 'aaaa0001-0000-4000-8000-000000000002';
insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica)
values ((select id from espaco),
        'aaaa0001-0000-4000-8000-000000000002', 'telefone_no_diretorio', 'politica-2026-01');


-- ===========================================================================
-- 4. As funções de apoio respondendo certo para cada pessoa
-- ===========================================================================

set local role authenticated;

-- Carla, colaboradora do setor Saúde.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
set local "request.jwt.claims" = '{"aal":"aal1"}';

select is((select private.pertence_ao_espaco((select id from espaco)))::text,
  'true', 'Quem tem vínculo em aberto pertence ao espaço, mesmo sem linha de membro da Redação');
select is((select private.vinculo_ativo())::text, 'true',
  'Quem tem vínculo confirmado tem vínculo vigente');
select is((select private.pertence_ao_setor((select id from setor where slug = 'saude')))::text,
  'true', 'Quem tem vínculo vigente no setor pertence ao setor');
select is((select private.pertence_ao_setor((select id from setor where slug = 'comunicacao')))::text,
  'false', 'Vínculo em um setor não faz a pessoa pertencer a outro setor');
select is((select private.alcance_do_diretorio()), 'completo',
  'Colaboradora com vínculo vigente enxerga o diretório inteiro');
select is((select private.mesmo_setor('aaaa0001-0000-4000-8000-000000000004'))::text, 'true',
  'Colaboradora e voluntário do mesmo setor compartilham setor');
select is((select private.mesmo_setor('aaaa0001-0000-4000-8000-000000000009'))::text, 'false',
  'Pessoas de setores diferentes não compartilham setor');
select is((select public.autorizar('pessoa.convidar'))::text, 'false',
  'Colaboradora comum não convida ninguém');
select is((select public.autorizar('documento.enviar'))::text, 'true',
  'Colaboradora comum envia documento');

-- Sérgio, que entrou e não tem vínculo nenhum.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000006';

select is((select private.pertence_ao_espaco((select id from espaco)))::text,
  'false', 'Quem não tem vínculo não pertence ao espaço');
select is((select private.vinculo_ativo())::text, 'false',
  'Quem não tem vínculo não tem vínculo vigente');
select is((select private.alcance_do_diretorio()), 'minimo',
  'Quem não tem vínculo fica no alcance mínimo do diretório');
select is((select count(*)::text from public.setores), '0',
  'Quem não tem vínculo não lê nem a lista de setores');
select is((select count(*)::text from public.profiles_diretorio), '0',
  'Quem não tem vínculo vigente não enxerga o diretório');

-- Nilza, voluntária recém-chegada, com vínculo ainda novo.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000005';

select is((select private.pertence_ao_espaco((select id from espaco)))::text,
  'true', 'Voluntária recém-chegada já pertence ao espaço, porque o vínculo não está encerrado');
select is((select private.vinculo_ativo())::text, 'false',
  'Voluntária com vínculo ainda novo não tem vínculo vigente');
select is((select private.alcance_do_diretorio()), 'minimo',
  'Voluntária com vínculo ainda novo fica no alcance mínimo do diretório');

-- Vítor, voluntário com vínculo confirmado e sem linha de membro da Redação.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000004';

select is((select private.alcance_do_diretorio()), 'setor',
  'Voluntário com vínculo confirmado enxerga o diretório do próprio setor');
select ok((select count(*) from public.setores) > 0,
  'Voluntário com vínculo e sem linha de membro da Redação lê a lista de setores');
select lives_ok($$
  insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica)
  select w.id, 'aaaa0001-0000-4000-8000-000000000004', 'imagem', 'politica-2026-01'
  from espaco w
$$, 'Voluntário com vínculo e sem linha de membro da Redação grava o próprio consentimento');

-- Clara, coordenadora do setor Saúde.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000003';

select is((select private.tem_papel('coordenador', (select id from setor where slug = 'saude')))::text,
  'true', 'A coordenadora tem o papel no setor em que foi nomeada');
select is((select private.tem_papel('coordenador', (select id from setor where slug = 'comunicacao')))::text,
  'false', 'Papel de setor não vale em outro setor');
select is((select public.autorizar('pessoa.convidar', (select id from setor where slug = 'saude')))::text,
  'true', 'A coordenadora convida para o próprio setor');
select is((select public.autorizar('pessoa.convidar', (select id from setor where slug = 'comunicacao')))::text,
  'false', 'A coordenadora não convida para setor que não é dela');
select is((select public.autorizar('operacao.administrar'))::text, 'false',
  'A coordenadora não administra a instalação');

-- Sônia, da Secretaria.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';

select is((select private.alcance_do_diretorio()), 'completo',
  'Quem lê dado restrito enxerga o diretório inteiro');
select is((select public.autorizar('pessoa.ver_restrito'))::text, 'true',
  'A Secretaria lê o cadastro restrito');
select is((select public.autorizar('pessoa.confirmar_vinculo'))::text, 'true',
  'A Secretaria confirma vínculo');
select is((select public.autorizar('operacao.administrar'))::text, 'false',
  'A Secretaria não administra a instalação: isso é do administrador');

-- Paulo, parceiro externo.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000008';
select is((select private.alcance_do_diretorio()), 'minimo',
  'Parceiro externo fica no alcance mínimo do diretório');

-- Segundo fator: a sessão é que diz, não o perfil.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
set local "request.jwt.claims" = '{"aal":"aal1"}';
select is((select private.exige_aal2())::text, 'false',
  'Sessão sem segundo fator não passa na exigência de segundo fator');
set local "request.jwt.claims" = '{"aal":"aal2"}';
select is((select private.exige_aal2())::text, 'true',
  'Sessão com segundo fator passa na exigência de segundo fator');

-- Tolerância: sem a lista de papéis no crachá, a resposta vem do banco.
set local "request.jwt.claims" = '{"aal":"aal1"}';
select is((select public.autorizar('pessoa.convidar'))::text, 'true',
  'Sem a lista de papéis no crachá, a autorização é respondida pelo banco');
set local "request.jwt.claims" = '{"aal":"aal1","papeis":[]}';
select is((select public.autorizar('pessoa.convidar'))::text, 'true',
  'Crachá com lista de papéis vazia também cai para a resposta do banco');
set local "request.jwt.claims" = '{"aal":"aal1","papeis":[{"papel":"voluntario","setor_id":null}]}';
select is((select public.autorizar('pessoa.convidar'))::text, 'false',
  'Com lista de papéis no crachá, vale o crachá: papel de voluntário não convida');

reset role;


-- ===========================================================================
-- 5. O diretório mostra o que a matriz de papéis promete
-- ===========================================================================

set local role authenticated;
set local "request.jwt.claims" = '{"aal":"aal1"}';

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select is(
  (select string_agg(username, ',' order by username) from public.profiles_diretorio),
  'carla,clara,heloisa,vitor',
  'Colaboradora vê a si, quem se abriu a todos e quem é do seu setor');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000004';
select is(
  (select string_agg(username, ',' order by username) from public.profiles_diretorio),
  'carla,clara,heloisa,vitor',
  'Voluntário com vínculo confirmado vê apenas gente do seu setor');

-- ACHADO: este teste reprova. A seção 5.2 promete que quem está no alcance
-- mínimo vê coordenadores, Secretaria e Voluntariado. A view do diretório roda
-- com os privilégios de quem consulta, e a regra de linha de usuario_papeis só
-- deixa a pessoa ler os papéis dela própria, então a parte de coordenação e
-- Secretaria da lista nunca aparece para quem está no mínimo.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000005';
select is(
  (select string_agg(username, ',' order by username) from public.profiles_diretorio),
  'clara,sonia',
  'Voluntária ainda nova vê só coordenação, Secretaria e Voluntariado');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000008';
select is(
  (select count(*)::text from public.profiles_diretorio
    where username in ('carla','heloisa','ester','vitor','dora')),
  '0',
  'Parceiro externo não enxerga a equipe da casa no diretório');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
select is(
  (select count(*)::text from public.profiles_diretorio),
  '12',
  'A Secretaria vê todo mundo com vínculo confirmado');
select is(
  (select count(*)::text from public.profiles_diretorio where username = 'dora'),
  '1',
  'Quem se escondeu do diretório continua visível para a Secretaria');
select is(
  (select count(*)::text from public.profiles_diretorio where username = 'nilza'),
  '0',
  'Ninguém aparece no diretório antes de o vínculo ser confirmado');
select is(
  (select count(*)::text from public.profiles_diretorio where username = 'robo'),
  '0',
  'Conta de serviço não é gente e não aparece no diretório');
select is(
  (select count(*)::text from public.profiles_diretorio where username = 'flavia'),
  '0',
  'Perfil de outro espaço não aparece no diretório deste espaço');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select is(
  (select count(*)::text from public.profiles_diretorio where username = 'dora'),
  '0',
  'Quem se escondeu do diretório some para a colega');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000015';
select is(
  (select string_agg(username, ',' order by username) from public.profiles_diretorio),
  'flavia',
  'Quem só tem vínculo no outro espaço não vê ninguém deste espaço');

-- Telefone: as três condições cumulativas da seção 6.6.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000003';
select is(
  (select telefone from public.profiles_diretorio where username = 'carla'),
  null::text,
  'A coordenadora não vê o telefone da colega, porque não lê dado restrito');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000010';
select is(
  (select telefone from public.profiles_diretorio where username = 'carla'),
  '21999990000',
  'O administrador vê o telefone de quem marcou telefone visível e deu consentimento');

-- ACHADO: este teste reprova. A seção 6.6 diz que o telefone aparece quando
-- quem consulta lê dado restrito, a pessoa marcou telefone visível e há
-- consentimento vigente, e nomeia a Secretaria como quem lê dado restrito. Mas
-- a view roda com os privilégios de quem consulta e a regra de linha de
-- consentimentos só abre a linha para o próprio titular, para quem responde
-- pedido de titular e para quem lê a trilha completa. A Secretaria não tem
-- nenhuma das duas permissões, então a checagem do consentimento dá falso e o
-- telefone nunca aparece para ela.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
select is(
  (select telefone from public.profiles_diretorio where username = 'carla'),
  '21999990000',
  'A Secretaria vê o telefone de quem marcou telefone visível e deu consentimento');

reset role;

-- Consentimento de telefone revogado tira o telefone da lista, para todo mundo.
update public.consentimentos set revogado_em = now()
 where profile_id = 'aaaa0001-0000-4000-8000-000000000002' and finalidade = 'telefone_no_diretorio';

set local role authenticated;
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000010';
select is(
  (select telefone from public.profiles_diretorio where username = 'carla'),
  null::text,
  'Revogado o consentimento, o telefone some do diretório na hora');
reset role;

insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica)
values ((select id from espaco),
        'aaaa0001-0000-4000-8000-000000000002', 'telefone_no_diretorio', 'politica-2026-02');


-- ===========================================================================
-- 6. Papel: escopo, exclusividade e teto
-- ===========================================================================

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000012', 'coordenador', null
  from espaco w
$$, '23514'::char(5), null,
  'Papel de setor não é concedido sem dizer qual setor');

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000012', 'secretaria', s.id
  from espaco w, setor s
  where s.slug = 'saude'
$$, '23514'::char(5), null,
  'Papel que vale na filial inteira não é preso a um setor');

select lives_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000012', 'coordenador', s.id
  from espaco w, setor s
  where s.slug = 'grd'
$$, 'Papel de setor é concedido quando o setor vem junto');

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000012', 'auditor', null
  from espaco w
$$, '23514'::char(5), null,
  'Quem já escreve não vira auditor: auditoria não convive com papel de escrita');

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000007', 'colaborador', null
  from espaco w
$$, '23514'::char(5), null,
  'Quem é auditor não ganha papel de escrita');

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000013', 'administrador', null
  from espaco w
$$, '23514'::char(5), null,
  'Administrador cabe a duas pessoas: a terceira concessão é recusada');

select lives_ok($$
  update public.usuario_papeis set fim = now()
  where user_id = 'aaaa0001-0000-4000-8000-000000000011' and papel = 'administrador'
$$, 'Uma das duas concessões de administrador pode ser encerrada');

select lives_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000013', 'administrador', null
  from espaco w
$$, 'Encerrada uma concessão, entra outro administrador no lugar');

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000002', 'colaborador', null
  from espaco w
$$, '23505'::char(5), null,
  'O mesmo papel não é concedido duas vezes à mesma pessoa no mesmo setor');

-- ACHADO: este teste reprova. A seção 5.3 promete que auditor e parceiro
-- externo são mutuamente exclusivos com qualquer papel de escrita, conferido
-- pelo mesmo gatilho. O gatilho decide pela marca de papel só de leitura, e no
-- seed essa marca é verdadeira apenas para auditor: parceiro externo nasce como
-- papel de escrita e ainda recebe a permissão de assinar autorização.
select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000008', 'colaborador', null
  from espaco w
$$, '23514'::char(5), null,
  'Quem é parceiro externo não ganha papel de escrita');

select is(
  (select exige_mfa::text from public.papeis where slug = 'secretaria'), 'true',
  'A Secretaria é papel que exige segundo fator');
select is(
  (select exige_mfa::text from public.papeis where slug = 'coordenador'), 'false',
  'A coordenação ainda não é obrigada ao segundo fator nesta rodada');
select is(
  (select somente_leitura::text from public.papeis where slug = 'auditor'), 'true',
  'O auditor é papel que só lê');
select is(
  (select count(*)::text from public.papel_permissoes
    where papel = 'diretoria' and permissao = 'documento.permissionar'),
  '0',
  'A Diretoria não recebe o poder de permissionar pasta de todos os setores');
select is(
  (select count(*)::text from public.papel_permissoes
    where papel = 'auditor' and permissao <> 'trilha.ler_completa'),
  '0',
  'O auditor só recebe permissão de leitura da trilha');


-- ===========================================================================
-- 7. Quem pode escrever o quê: as policies em ação
-- ===========================================================================

set local role authenticated;

-- A própria pessoa não escreve as colunas de segurança do próprio perfil.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
set local "request.jwt.claims" = '{"aal":"aal2"}';

select throws_ok($$
  update public.profiles set mfa_verificado_em = now()
  where id = 'aaaa0001-0000-4000-8000-000000000002'
$$, '42501'::char(5), null,
  'A própria pessoa não carimba a hora da sua verificação de segundo fator');

select throws_ok($$
  update public.profiles set setor_principal_id = (select id from setor where slug = 'diretoria')
  where id = 'aaaa0001-0000-4000-8000-000000000002'
$$, '42501'::char(5), null,
  'A própria pessoa não se muda de setor sozinha');

select lives_ok($$
  update public.profiles set apresentacao = 'Enfermeira, plantão noturno.'
  where id = 'aaaa0001-0000-4000-8000-000000000002'
$$, 'A própria pessoa edita a sua apresentação');

-- Confirmar vínculo é da Secretaria.
select throws_ok($$
  insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado)
  select w.id, 'aaaa0001-0000-4000-8000-000000000006', s.id, 'voluntario', 'new'
  from espaco w, setor s
  where s.slug = 'saude'
$$, '42501'::char(5), null,
  'Colaboradora comum não cria vínculo para ninguém');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
select lives_ok($$
  insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado)
  select w.id, 'aaaa0001-0000-4000-8000-000000000006', s.id, 'voluntario', 'new'
  from espaco w, setor s
  where s.slug = 'saude'
$$, 'A Secretaria cria o vínculo de quem entrou sem vínculo');

-- Conceder papel exige segundo fator e não alcança administrador nem auditor.
set local "request.jwt.claims" = '{"aal":"aal1"}';
select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000006', 'voluntario', null
  from espaco w
$$, '42501'::char(5), null,
  'Papel não é concedido em sessão sem segundo fator');

set local "request.jwt.claims" = '{"aal":"aal2"}';
select lives_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000006', 'voluntario', null
  from espaco w
$$, 'A Secretaria concede papel em sessão com segundo fator');

select throws_ok($$
  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
  select w.id, 'aaaa0001-0000-4000-8000-000000000015', 'auditor', null
  from espaco w
$$, '42501'::char(5), null,
  'Só o administrador concede os papéis de administrador e de auditor');

-- Cadastro restrito: coordenação não lê.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select lives_ok($$
  insert into public.profiles_restritos (profile_id, workspace_id, cpf)
  select 'aaaa0001-0000-4000-8000-000000000002', w.id, '12345678901'
  from espaco w
$$, 'A própria pessoa grava o seu cadastro restrito');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000003';
select is((select count(*)::text from public.profiles_restritos
            where profile_id = 'aaaa0001-0000-4000-8000-000000000002'),
  '0', 'A coordenadora não lê o cadastro restrito da sua equipe');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
select is((select count(*)::text from public.profiles_restritos
            where profile_id = 'aaaa0001-0000-4000-8000-000000000002'),
  '1', 'A Secretaria lê o cadastro restrito');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select is((select count(*)::text from public.profiles_restritos
            where profile_id = 'aaaa0001-0000-4000-8000-000000000002'),
  '1', 'A própria pessoa lê o seu cadastro restrito');

-- Delegação exige segundo fator e permissão de delegar.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000003';
set local "request.jwt.claims" = '{"aal":"aal1"}';
select throws_ok($$
  insert into public.delegacoes (workspace_id, delegante_id, delegado_id, papel, setor_id, criado_por)
  select w.id, 'aaaa0001-0000-4000-8000-000000000003', 'aaaa0001-0000-4000-8000-000000000002',
         'coordenador', s.id, 'aaaa0001-0000-4000-8000-000000000003'
  from espaco w, setor s
  where s.slug = 'saude'
$$, '42501'::char(5), null,
  'Delegação não é registrada em sessão sem segundo fator');

set local "request.jwt.claims" = '{"aal":"aal2"}';
select lives_ok($$
  insert into public.delegacoes (workspace_id, delegante_id, delegado_id, papel, setor_id, criado_por)
  select w.id, 'aaaa0001-0000-4000-8000-000000000003', 'aaaa0001-0000-4000-8000-000000000002',
         'coordenador', s.id, 'aaaa0001-0000-4000-8000-000000000003'
  from espaco w, setor s
  where s.slug = 'saude'
$$, 'A coordenadora registra a delegação da sua ausência em sessão com segundo fator');

select is((select private.delegacao_para('coordenador', (select id from setor where slug = 'saude')))::text,
  null::text, 'Quem delegou não vira delegado de si mesmo');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select isnt((select private.delegacao_para('coordenador', (select id from setor where slug = 'saude')))::text,
  null::text, 'Quem recebeu a delegação a encontra pelo papel e pelo setor');

-- Registro da verificação de segundo fator.
set local "request.jwt.claims" = '{"aal":"aal1"}';
select throws_ok($$ select public.registrar_verificacao_mfa() $$, '42501'::char(5), null,
  'A hora da verificação de segundo fator não é registrada em sessão sem segundo fator');

set local "request.jwt.claims" = '{"aal":"aal2"}';
select lives_ok($$ select public.registrar_verificacao_mfa() $$,
  'A hora da verificação de segundo fator é registrada em sessão com segundo fator');

reset role;
select isnt((select mfa_verificado_em from public.profiles where id = 'aaaa0001-0000-4000-8000-000000000002'),
  null::timestamptz, 'A hora da verificação fica gravada no perfil como espelho de leitura');


-- ===========================================================================
-- 8. Convite: prazo, uso único e alcance de quem convida
-- ===========================================================================

set local role authenticated;
set local "request.jwt.claims" = '{"aal":"aal1"}';

-- A coordenadora convida para o próprio setor, e só para ele.
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000003';
select lives_ok($$
  insert into public.convites (workspace_id, email, tipo_vinculo, setor_id, token_hash, criado_por)
  select w.id, 'Novato@Exemplo.Org', 'voluntario', s.id,
         encode(sha256(convert_to('token-do-novato','UTF8')),'hex'),
         'aaaa0001-0000-4000-8000-000000000003'
  from espaco w, setor s
  where s.slug = 'saude'
$$, 'A coordenadora convida para o seu próprio setor');

select throws_ok($$
  insert into public.convites (workspace_id, email, tipo_vinculo, setor_id, token_hash, criado_por)
  select w.id, 'outro@exemplo.org', 'voluntario', s.id,
         encode(sha256(convert_to('token-do-outro','UTF8')),'hex'),
         'aaaa0001-0000-4000-8000-000000000003'
  from espaco w, setor s
  where s.slug = 'comunicacao'
$$, '42501'::char(5), null,
  'A coordenadora não convida para setor que não é dela');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select throws_ok($$
  insert into public.convites (workspace_id, email, tipo_vinculo, setor_id, token_hash, criado_por)
  select w.id, 'terceiro@exemplo.org', 'voluntario', s.id,
         encode(sha256(convert_to('token-do-terceiro','UTF8')),'hex'),
         'aaaa0001-0000-4000-8000-000000000002'
  from espaco w, setor s
  where s.slug = 'saude'
$$, '42501'::char(5), null,
  'Colaboradora comum não convida ninguém');

reset role;

select is((select email from public.convites where email like '%novato%'), 'novato@exemplo.org',
  'O e-mail do convite é guardado normalizado, em minúsculas e sem sobra de espaço');
select ok((select expira_em from public.convites where email = 'novato@exemplo.org') > now() + interval '13 days',
  'O convite nasce com prazo de quatorze dias');

select is((select valido::text from public.consultar_convite('token-do-novato')), 'true',
  'O convite recém-criado é válido quando consultado pelo código');
select is((select email_mascarado from public.consultar_convite('token-do-novato')), 'n***@exemplo.org',
  'A consulta pública devolve o e-mail mascarado, nunca o e-mail inteiro');
select is((select count(*)::text from public.consultar_convite('token-que-nao-existe')), '0',
  'Código que não existe não devolve convite nenhum');

select throws_ok($$
  insert into public.convites (workspace_id, email, tipo_vinculo, setor_id, token_hash, criado_por)
  select w.id, 'novato@exemplo.org', 'voluntario', s.id,
         encode(sha256(convert_to('outro-token-do-novato','UTF8')),'hex'),
         'aaaa0001-0000-4000-8000-000000000001'
  from espaco w, setor s
  where s.slug = 'saude'
$$, '23505'::char(5), null,
  'Não há dois convites em aberto para o mesmo e-mail no mesmo espaço');

update public.convites
   set aceito_em = now(), aceito_por = 'aaaa0001-0000-4000-8000-000000000006'
 where email = 'novato@exemplo.org';

select is((select valido::text from public.consultar_convite('token-do-novato')), 'false',
  'Convite aceito não serve de novo');

select throws_ok($$
  update public.convites set revogado_em = now() where email = 'novato@exemplo.org'
$$, '23514'::char(5), null,
  'Convite já aceito não é revogado depois');

update public.convites set aceito_em = null, aceito_por = null, expira_em = now() - interval '1 day'
 where email = 'novato@exemplo.org';
select is((select valido::text from public.consultar_convite('token-do-novato')), 'false',
  'Convite fora do prazo não serve');


-- ===========================================================================
-- 9. Código de recuperação do segundo fator: uso único
-- ===========================================================================

create temporary table codigos_da_carla (codigo text) on commit drop;
grant select, insert on codigos_da_carla to authenticated;

set local role authenticated;
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
set local "request.jwt.claims" = '{"aal":"aal1"}';

insert into codigos_da_carla (codigo) select public.gerar_codigos_recuperacao();

select is((select count(*)::text from codigos_da_carla), '10',
  'A inscrição do segundo fator entrega dez códigos de recuperação');
select is((select count(distinct codigo)::text from codigos_da_carla), '10',
  'Os dez códigos de recuperação são todos diferentes');

reset role;
select is(
  (select count(*)::text from public.codigos_recuperacao c
    join codigos_da_carla k on k.codigo = c.hash),
  '0',
  'O código em claro nunca é guardado: a tabela só tem o resumo');

set local role authenticated;
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000002';
select is((select public.usar_codigo_recuperacao((select min(codigo) from codigos_da_carla)))::text,
  'true', 'O código de recuperação serve na primeira vez');
select is((select public.usar_codigo_recuperacao((select min(codigo) from codigos_da_carla)))::text,
  'false', 'O mesmo código de recuperação não serve uma segunda vez');
select is((select public.usar_codigo_recuperacao('codigo-que-ninguem-gerou'))::text,
  'false', 'Código inventado não serve');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000004';
select is((select public.usar_codigo_recuperacao((select max(codigo) from codigos_da_carla)))::text,
  'false', 'Código de recuperação de outra pessoa não serve');

reset role;
select is((select count(*)::text from public.codigos_recuperacao
            where profile_id = 'aaaa0001-0000-4000-8000-000000000002' and usado_em is not null),
  '1', 'Só o código realmente usado fica marcado como usado');


-- ===========================================================================
-- 10. Consentimento é prova, e dado sensível depende dele
-- ===========================================================================

select throws_ok($$
  update public.consentimentos set finalidade = 'whatsapp'
  where profile_id = 'aaaa0001-0000-4000-8000-000000000004' and finalidade = 'imagem'
    and revogado_em is null
$$, '23514'::char(5), null,
  'Consentimento gravado não é reescrito: só a revogação pode mudar');

select lives_ok($$
  update public.consentimentos set revogado_em = now()
  where profile_id = 'aaaa0001-0000-4000-8000-000000000004' and finalidade = 'imagem'
$$, 'O titular revoga o consentimento a qualquer momento');

select throws_ok($$
  update public.consentimentos set revogado_em = null
  where profile_id = 'aaaa0001-0000-4000-8000-000000000004' and finalidade = 'imagem'
$$, '23514'::char(5), null,
  'Revogação de consentimento não se desfaz');

select lives_ok($$
  insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica)
  select w.id, 'aaaa0001-0000-4000-8000-000000000004', 'imagem', 'politica-2026-02'
  from espaco w
$$, 'Depois de revogar, consentir de novo é linha nova, e a antiga fica de prova');

select is((select count(*)::text from public.consentimentos
            where profile_id = 'aaaa0001-0000-4000-8000-000000000004' and finalidade = 'imagem'),
  '2', 'A linha do consentimento revogado nunca some');

select throws_ok($$
  insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica)
  select w.id, 'aaaa0001-0000-4000-8000-000000000004', 'imagem', 'politica-2026-03'
  from espaco w
$$, '23505'::char(5), null,
  'Não há dois consentimentos vigentes da mesma finalidade para a mesma pessoa');

select throws_ok($$
  update public.profiles_restritos set tipo_sanguineo = 'O+'
  where profile_id = 'aaaa0001-0000-4000-8000-000000000002'
$$, '23514'::char(5), null,
  'Tipo sanguíneo não entra sem consentimento vigente de finalidade saúde');

insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica)
values ((select id from espaco),
        'aaaa0001-0000-4000-8000-000000000002', 'saude', 'politica-2026-01');

select lives_ok($$
  update public.profiles_restritos set tipo_sanguineo = 'O+'
  where profile_id = 'aaaa0001-0000-4000-8000-000000000002'
$$, 'Com consentimento vigente de finalidade saúde, o tipo sanguíneo entra');

set local role authenticated;
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
set local "request.jwt.claims" = '{"aal":"aal2"}';
select throws_ok($$
  insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica, origem, registrado_por)
  select w.id, 'aaaa0001-0000-4000-8000-000000000004', 'whatsapp', 'politica-2026-01',
         'papel', 'aaaa0001-0000-4000-8000-000000000001'
  from espaco w
$$, '42501'::char(5), null,
  'Consentimento colhido em papel não entra sem o comprovante digitalizado anexado');

set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000004';
select throws_ok($$
  insert into public.consentimentos (workspace_id, profile_id, finalidade, versao_politica, origem)
  select w.id, 'aaaa0001-0000-4000-8000-000000000004', 'whatsapp', 'politica-2026-01', 'papel'
  from espaco w
$$, '42501'::char(5), null,
  'O titular grava o seu consentimento como de origem interna, nunca como colhido em papel');
reset role;


-- ===========================================================================
-- 11. Idade mínima, conta de serviço e vínculo herdado
-- ===========================================================================

select throws_ok($$
  insert into public.profiles_restritos (profile_id, workspace_id, data_nascimento)
  select 'aaaa0001-0000-4000-8000-000000000004', w.id, current_date - interval '17 years'
  from espaco w
$$, '23514'::char(5), null,
  'Cadastro restrito de quem ainda não tem dezoito anos é recusado');

select lives_ok($$
  insert into public.profiles_restritos (profile_id, workspace_id, data_nascimento)
  select 'aaaa0001-0000-4000-8000-000000000004', w.id, current_date - interval '30 years'
  from espaco w
$$, 'Cadastro restrito de pessoa maior de idade é aceito');

select throws_ok($$
  insert into public.profiles_restritos (profile_id, workspace_id, cpf)
  select 'aaaa0001-0000-4000-8000-000000000016', w.id, '98765432100'
  from espaco w
$$, '23514'::char(5), null,
  'Conta de serviço não tem dado pessoal e não recebe cadastro restrito');

select is(
  (select estado from public.vinculos where profile_id = 'aaaa0001-0000-4000-8000-000000000013'),
  'active',
  'Vínculo herdado na carga inicial continua vigente mesmo sem formação registrada');
select is(
  (select count(*)::text from public.formacoes where profile_id = 'aaaa0001-0000-4000-8000-000000000013'),
  '0',
  'O vínculo herdado segue vigente sem nenhuma formação lançada');
select is(
  (select count(*)::text from public.termos_adesao
    where profile_id = 'aaaa0001-0000-4000-8000-000000000013' and status = 'signed'),
  '0',
  'O vínculo herdado segue vigente sem termo de adesão reassinado');
select is(
  (select origem from public.vinculos where profile_id = 'aaaa0001-0000-4000-8000-000000000013'),
  'carga_inicial',
  'O vínculo herdado fica marcado como vindo da carga inicial');

select throws_ok($$
  insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado)
  select w.id, 'aaaa0001-0000-4000-8000-000000000002', s.id, 'colaborador', 'active'
  from espaco w, setor s
  where s.slug = 'saude'
$$, '23505'::char(5), null,
  'A mesma pessoa não tem dois vínculos em aberto no mesmo setor e do mesmo tipo');

select throws_ok($$
  update public.vinculos set estado = 'terminated'
  where profile_id = 'aaaa0001-0000-4000-8000-000000000013'
$$, '23514'::char(5), null,
  'Vínculo encerrado sem data de fim é recusado');

select throws_ok($$
  insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado)
  select w.id, 'aaaa0001-0000-4000-8000-000000000006', s.id, 'estagiario', 'new'
  from espaco w, setor s
  where s.slug = 'grd'
$$, '23514'::char(5), null,
  'Tipo de vínculo que não está no escopo é recusado');

-- Desligamento: quem sai do diretório sai na hora.
update public.profiles set desativado_em = now()
 where id = 'aaaa0001-0000-4000-8000-000000000013';
select is((select active::text from public.profiles where id = 'aaaa0001-0000-4000-8000-000000000013'),
  'false', 'Desligar a pessoa apaga a marca de ativa que a Redação ainda lê');

set local role authenticated;
set local "request.jwt.claim.sub" = 'aaaa0001-0000-4000-8000-000000000001';
set local "request.jwt.claims" = '{"aal":"aal1"}';
select is((select count(*)::text from public.profiles_diretorio where username = 'heloisa'),
  '0', 'Quem foi desligada some do diretório no mesmo instante');
reset role;


-- ===========================================================================
-- 12. O crachá que o hook de token emite
-- ===========================================================================

select is(
  public.custom_access_token_hook(
    jsonb_build_object('user_id', 'aaaa0001-0000-4000-8000-000000000003', 'claims', '{}'::jsonb)
  ) #>> '{claims,papel_global}',
  'coordenador',
  'O crachá traz o papel de maior alcance de quem entrou');

select is(
  public.custom_access_token_hook(
    jsonb_build_object('user_id', 'aaaa0001-0000-4000-8000-000000000003', 'claims', '{}'::jsonb)
  ) #>> '{claims,vinculo,estado}',
  'active',
  'O crachá traz o estado do vínculo de quem entrou');

select is(
  (select count(*)::text from jsonb_array_elements(
     public.custom_access_token_hook(
       jsonb_build_object('user_id', 'aaaa0001-0000-4000-8000-000000000003', 'claims', '{}'::jsonb)
     ) #> '{claims,papeis}') as p
   where p ->> 'papel' = 'coordenador'),
  '1',
  'O crachá lista o papel com o setor em que ele vale');

select is(
  public.custom_access_token_hook(
    jsonb_build_object('user_id', 'aaaa0001-0000-4000-8000-000000000009', 'claims', '{}'::jsonb)
  ) #>> '{claims,papel_global}',
  'administrador',
  'Quem só tem cadastro antigo da Redação recebe o papel equivalente, e não fica sem papel');

select is(
  public.custom_access_token_hook(
    jsonb_build_object('user_id', 'aaaa0001-0000-4000-8000-000000000015', 'claims', '{}'::jsonb)
  ) #>> '{claims,papel_global}',
  null::text,
  'Quem não tem papel nenhum recebe crachá sem papel, e as policies negam o que exige papel');

select is(
  public.custom_access_token_hook('{"user_id": "isto-nao-e-um-identificador", "claims": {}}'::jsonb),
  '{"user_id": "isto-nao-e-um-identificador", "claims": {}}'::jsonb,
  'Erro no cálculo do crachá devolve o crachá intacto e nunca barra a entrada');


select * from finish();
rollback;


-- ============================================================
-- 02. Contato e mural por setor
-- ============================================================

-- Testes pgTAP da area de contato e mural por setor (fases 1 e 2 do escopo).
-- Cobre grupos, membros de grupo, avisos, publico do aviso, confirmacao de
-- leitura, comentarios, notificacoes e mensagem direta.
--
-- Como rodar:
--   /pgtest/novo_banco.sh t_mural
--   psql -h /pgtest/sock -U postgres -d t_mural -f testes-02-mural.sql
--
-- Convencao das sessoes fingidas: toda leitura e toda escrita de uma pessoa
-- passa por uma das quatro funcoes auxiliares abaixo, que trocam para o papel
-- authenticated e gravam o "sub" do JWT. O motivo de nao trocar de papel na
-- linha do proprio teste e que as funcoes do pgTAP escrevem em tabelas
-- temporarias que so o dono do banco alcanca.

\set ON_ERROR_STOP on

begin;

select plan(118);

-- ---------------------------------------------------------------------------
-- Auxiliares
-- ---------------------------------------------------------------------------

-- Roda o comando como dono do banco e desfaz o efeito, devolvendo 'ok' quando
-- o modelo aceitou e o codigo do erro quando recusou.
create function pg_temp.testa(p_sql text) returns text
language plpgsql as $fn$
begin
  execute p_sql;
  raise exception using errcode = 'UT000';
exception
  when sqlstate 'UT000' then return 'ok';
  when others then return sqlstate;
end;
$fn$;

-- Mesma ideia, na sessao de uma pessoa: troca para authenticated, finge o JWT
-- e desfaz o efeito.
create function pg_temp.como(p_user uuid, p_sql text, p_claims text default null)
returns text language plpgsql as $fn$
begin
  perform set_config('request.jwt.claim.sub', p_user::text, true);
  perform set_config('request.jwt.claims', coalesce(p_claims, ''), true);
  execute 'set local role authenticated';
  execute p_sql;
  execute 'reset role';
  raise exception using errcode = 'UT000';
exception
  when sqlstate 'UT000' then
    execute 'reset role';
    return 'ok';
  when others then
    execute 'reset role';
    return sqlstate;
end;
$fn$;

-- Quantas linhas o comando alcancou na sessao daquela pessoa, ou o codigo do
-- erro. Serve para separar "a policy recusou" de "a policy nao viu linha".
create function pg_temp.linhas(p_user uuid, p_sql text, p_claims text default null)
returns text language plpgsql as $fn$
declare n bigint;
begin
  perform set_config('request.jwt.claim.sub', p_user::text, true);
  perform set_config('request.jwt.claims', coalesce(p_claims, ''), true);
  execute 'set local role authenticated';
  execute p_sql;
  get diagnostics n = row_count;
  execute 'reset role';
  raise exception using errcode = 'UT000', message = n::text;
exception
  when sqlstate 'UT000' then
    execute 'reset role';
    return sqlerrm;
  when others then
    execute 'reset role';
    return sqlstate;
end;
$fn$;

-- Leitura na sessao de uma pessoa, com o efeito preservado.
create function pg_temp.le(p_user uuid, p_sql text, p_claims text default null)
returns text language plpgsql as $fn$
declare v text;
begin
  perform set_config('request.jwt.claim.sub', p_user::text, true);
  perform set_config('request.jwt.claims', coalesce(p_claims, ''), true);
  execute 'set local role authenticated';
  execute p_sql into v;
  execute 'reset role';
  return v;
end;
$fn$;

-- ---------------------------------------------------------------------------
-- Gente, grupos e avisos de mentira
-- ---------------------------------------------------------------------------

-- Coordenadora da Saude e dona do mural da Saude.
\set coord '''c0000000-0000-4000-8000-000000000001'''
-- Voluntaria com vinculo ativo na Saude, membro do mural.
\set ana '''a0000000-0000-4000-8000-000000000002'''
-- Voluntario do Voluntariado que tambem entrou no mural da Saude.
\set bruno '''b0000000-0000-4000-8000-000000000003'''
-- Secretaria.
\set sec '''5ec00000-0000-4000-8000-000000000004'''
-- Administradora.
\set adm '''ad000000-0000-4000-8000-000000000005'''
-- Colaborador do espaco que nao entrou no mural da Saude.
\set fora '''f0000000-0000-4000-8000-000000000006'''

\set g_saude '''61000000-0000-4000-8000-000000000001'''
\set g_geral '''61000000-0000-4000-8000-000000000002'''

\set a_setor    '''a5000000-0000-4000-8000-000000000001'''
\set a_rascunho '''a5000000-0000-4000-8000-000000000002'''
\set a_vencido  '''a5000000-0000-4000-8000-000000000003'''
\set a_obrig    '''a5000000-0000-4000-8000-000000000004'''
\set a_agendado '''a5000000-0000-4000-8000-000000000005'''

\set msg '''e0000000-0000-4000-8000-000000000001'''
\set com '''cccc0000-0000-4000-8000-000000000001'''

\set aal2 '''{"aal":"aal2"}'''

do $carga$
declare
  v_ws    uuid := (select id from public.workspaces where slug = 'producao');
  v_saude uuid := (select id from public.setores where slug = 'saude');
  v_volu  uuid := (select id from public.setores where slug = 'voluntariado');
  v_coord uuid := 'c0000000-0000-4000-8000-000000000001';
  v_ana   uuid := 'a0000000-0000-4000-8000-000000000002';
  v_bruno uuid := 'b0000000-0000-4000-8000-000000000003';
  v_sec   uuid := '5ec00000-0000-4000-8000-000000000004';
  v_adm   uuid := 'ad000000-0000-4000-8000-000000000005';
  v_fora  uuid := 'f0000000-0000-4000-8000-000000000006';
  v_gs    uuid := '61000000-0000-4000-8000-000000000001';
  v_gg    uuid := '61000000-0000-4000-8000-000000000002';
begin
  -- Sem e-mail o gatilho de novo usuario nao monta perfil sozinho, e a carga
  -- fica sob controle do teste.
  insert into auth.users (id) values (v_coord),(v_ana),(v_bruno),(v_sec),(v_adm),(v_fora);

  insert into public.profiles (id, username, full_name, tipo_conta) values
    (v_coord,'coord','Coordenadora da Saude','equipe'),
    (v_ana,  'ana',  'Ana Voluntaria',       'voluntario'),
    (v_bruno,'bruno','Bruno Voluntario',     'voluntario'),
    (v_sec,  'sec',  'Secretaria da Filial', 'equipe'),
    (v_adm,  'adm',  'Administradora',       'equipe'),
    (v_fora, 'fora', 'Colaborador de Fora',  'equipe');

  insert into public.workspace_members (workspace_id, user_id, role) values
    (v_ws,v_coord,'editor'),(v_ws,v_ana,'colaborador'),(v_ws,v_bruno,'colaborador'),
    (v_ws,v_sec,'editor'),(v_ws,v_adm,'admin'),(v_ws,v_fora,'colaborador');

  insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado) values
    (v_ws,v_coord,v_saude,'colaborador','active'),
    (v_ws,v_ana,  v_saude,'voluntario', 'active'),
    (v_ws,v_bruno,v_volu, 'voluntario', 'active'),
    (v_ws,v_sec,  v_saude,'colaborador','active'),
    (v_ws,v_adm,  v_saude,'colaborador','active'),
    (v_ws,v_fora, v_volu, 'colaborador','active');

  insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id) values
    (v_ws,v_coord,'coordenador',  v_saude),
    (v_ws,v_sec,  'secretaria',   null),
    (v_ws,v_adm,  'administrador',null),
    (v_ws,v_ana,  'voluntario',   null),
    (v_ws,v_bruno,'voluntario',   null);

  -- Mural da Saude: grupo de setor, comunidade, com moderacao de comentario.
  insert into public.grupos
    (id, workspace_id, tipo, setor_id, slug, nome, visibilidade, entrada,
     dono_id, criado_por, comentarios, comentarios_moderados)
  values
    (v_gs, v_ws, 'setor', v_saude, 'saude', 'Mural da Saude',
     'comunidade', 'por_pedido', v_coord, v_coord, true, true);

  -- Mural geral: um so, publico e de entrada aberta.
  insert into public.grupos
    (id, workspace_id, tipo, setor_id, slug, nome, visibilidade, entrada,
     dono_id, criado_por)
  values
    (v_gg, v_ws, 'geral', null, 'geral', 'Mural geral',
     'publica', 'aberta', v_adm, v_adm);

  insert into public.grupo_membros (workspace_id, grupo_id, user_id, papel, status, origem) values
    (v_ws,v_gs,v_coord,'dono',   'member','setor'),
    (v_ws,v_gs,v_ana,  'membro', 'member','setor'),
    (v_ws,v_gs,v_bruno,'membro', 'member','manual'),
    (v_ws,v_gs,v_sec,  'membro', 'member','manual');

  -- Aviso publicado com publico restrito ao setor Saude.
  insert into public.avisos
    (id, workspace_id, grupo_id, autor_id, titulo, corpo, status, publicado_em)
  values
    ('a5000000-0000-4000-8000-000000000001', v_ws, v_gs, v_coord,
     'Escala de plantao da Saude', 'Corpo do aviso.', 'published', now());
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo, setor_id)
  values (v_ws, 'a5000000-0000-4000-8000-000000000001', 'setor', v_saude);

  -- Comentario ja aprovado nesse aviso.
  insert into public.comentarios
    (id, workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo,
     status, moderado_por, moderado_em)
  values
    ('cccc0000-0000-4000-8000-000000000001', v_ws, 'aviso',
     'a5000000-0000-4000-8000-000000000001', v_gs, v_ana,
     'Anotei o plantao, obrigada.', 'approved', v_coord, now());

  -- Rascunho, ainda na redacao.
  insert into public.avisos
    (id, workspace_id, grupo_id, autor_id, titulo, corpo, status)
  values
    ('a5000000-0000-4000-8000-000000000002', v_ws, v_gs, v_coord,
     'Rascunho da coordenacao', 'Corpo do rascunho.', 'draft');

  -- Publicado, mas com a vigencia encerrada ontem.
  insert into public.avisos
    (id, workspace_id, grupo_id, autor_id, titulo, corpo, status,
     vigencia_inicio, vigencia_fim, publicado_em)
  values
    ('a5000000-0000-4000-8000-000000000003', v_ws, v_gs, v_coord,
     'Mutirao de marco', 'Corpo do aviso vencido.', 'published',
     now() - interval '60 days', now() - interval '1 day', now() - interval '60 days');

  -- Aguardando aprovacao, de leitura obrigatoria, para todo o mural.
  insert into public.avisos
    (id, workspace_id, grupo_id, autor_id, titulo, corpo, status,
     leitura_obrigatoria, motivo_obrigatoriedade, prazo_leitura)
  values
    ('a5000000-0000-4000-8000-000000000004', v_ws, v_gs, v_coord,
     'Protocolo de seguranca em campo', 'Corpo do protocolo.', 'pending_approval',
     true, 'seguranca_operacional', now() + interval '7 days');
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo)
  values (v_ws, 'a5000000-0000-4000-8000-000000000004', 'todos');

  -- Rascunho cuja vigencia so comeca daqui a dez dias.
  insert into public.avisos
    (id, workspace_id, grupo_id, autor_id, titulo, corpo, status,
     vigencia_inicio, vigencia_fim)
  values
    ('a5000000-0000-4000-8000-000000000005', v_ws, v_gs, v_coord,
     'Calendario do proximo trimestre', 'Corpo do calendario.', 'draft',
     now() + interval '10 days', now() + interval '40 days');

  -- Mensagem direta de Ana para a coordenadora.
  insert into public.messages (id, workspace_id, author_id, recipient_id, body)
  values ('e0000000-0000-4000-8000-000000000001', v_ws, v_ana, v_coord,
          'Coordenadora, posso trocar meu plantao de sabado?');
end
$carga$;

-- O identificador do espaco entra por aqui nas sessoes fingidas, porque quem
-- entrou na intranet nao tem permissao de leitura em public.workspaces.
select quote_literal(quote_literal(id)) as ws_lit from public.workspaces where slug = 'producao' \gset


-- ===========================================================================
-- 1. Estrutura: as tabelas e colunas em que o mural e os grupos moram
-- ===========================================================================

select has_table('public','grupos',
  'o espaco de contato guarda cada grupo numa tabela propria');
select has_table('public','grupo_membros',
  'quem pertence a um grupo, e com que papel, fica registrado em tabela propria');
select has_table('public','avisos',
  'cada aviso do mural e uma linha de tabela, e nao um documento solto');
select has_table('public','aviso_publicos',
  'o publico do aviso e feito de segmentos gravados, um por linha');
select has_table('public','aviso_leituras',
  'a confirmacao de leitura de cada destinatario tem tabela propria');
select has_table('public','comentarios',
  'os comentarios do mural moram numa tabela generica de comentario');
select has_table('public','notifications',
  'o sino de notificacoes tem tabela propria');
select has_table('public','messages',
  'a mensagem direta reaproveita a tabela de mensagens da Redacao');

select hasnt_table('public','murais',
  'nao existe tabela de mural: o mural e a aba de um grupo');

select has_column('public','avisos','motivo_obrigatoriedade',
  'o aviso guarda por que a leitura dele foi tornada obrigatoria');
select has_column('public','avisos','prazo_leitura',
  'o aviso guarda ate quando a leitura precisa ser confirmada');
select has_column('public','avisos','versao',
  'o aviso guarda o numero da versao, que sobe quando o corpo muda depois de publicado');
select col_type_is('public','avisos','anexos','uuid[]',
  'os anexos do aviso sao uma lista de identificadores de documento, sem tabela de ligacao');
select has_column('public','aviso_leituras','origem_abertura',
  'a leitura guarda por onde a pessoa abriu o aviso');
select has_column('public','aviso_leituras','versao',
  'a leitura guarda a que versao do aviso a confirmacao se refere');
select has_column('public','grupos','exige_aprovacao_previa',
  'a governanca do mural mora no grupo, inclusive a exigencia de aprovacao previa');
select has_column('public','grupos','revisao_em',
  'o grupo guarda a data da proxima revisao trimestral do mural');
select has_column('public','messages','lido_em',
  'a mensagem direta guarda quando o destinatario a leu');
select has_column('public','notifications','tipo',
  'a notificacao guarda o tipo do evento que a gerou');

-- Restricoes que valem regra de negocio.

select is(pg_temp.testa($$
  insert into public.avisos (workspace_id, grupo_id, autor_id, titulo, corpo, leitura_obrigatoria)
  select w.id, '61000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001',
         'Sem justificativa', 'corpo', true
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'aviso de leitura obrigatoria sem a justificativa escolhida na lista fechada e recusado');

select is(pg_temp.testa($$
  insert into public.avisos (workspace_id, grupo_id, autor_id, titulo, corpo,
                             leitura_obrigatoria, motivo_obrigatoriedade, prazo_leitura)
  select w.id, '61000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001',
         'Com justificativa', 'corpo', true, 'obrigacao_legal', now() + interval '5 days'
  from public.workspaces w where w.slug = 'producao'
$$), 'ok',
  'aviso de leitura obrigatoria com justificativa e prazo e aceito');

select is(pg_temp.testa($$
  insert into public.avisos (workspace_id, grupo_id, autor_id, titulo, corpo,
                             leitura_obrigatoria, motivo_obrigatoriedade, prazo_leitura)
  select w.id, '61000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001',
         'Motivo inventado', 'corpo', true, 'porque_sim', now() + interval '5 days'
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'justificativa de obrigatoriedade fora das tres previstas e recusada');

select is(pg_temp.testa($$
  insert into public.avisos (workspace_id, grupo_id, autor_id, titulo, corpo,
                             leitura_obrigatoria, motivo_obrigatoriedade)
  select w.id, '61000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001',
         'Sem prazo', 'corpo', true, 'obrigacao_legal'
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'aviso de leitura obrigatoria sem prazo para confirmar e recusado');

select is(pg_temp.testa($$
  insert into public.avisos (workspace_id, grupo_id, autor_id, titulo, corpo,
                             vigencia_inicio, vigencia_fim)
  select w.id, '61000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001',
         'Vigencia ao contrario', 'corpo', now(), now() - interval '1 day'
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'aviso que termina antes de comecar e recusado');

select is(pg_temp.testa($$
  update public.avisos set status = 'publicado'
  where id = 'a5000000-0000-4000-8000-000000000002'
$$), '23514',
  'estado de aviso fora da lista dos sete estados previstos e recusado');

select is(pg_temp.testa($$
  update public.avisos set status = 'rejected'
  where id = 'a5000000-0000-4000-8000-000000000002'
$$), '23514',
  'devolver um aviso ao autor sem escrever o motivo da devolucao e recusado');

select is(pg_temp.testa($$
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo)
  select w.id, 'a5000000-0000-4000-8000-000000000002', 'setor'
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'segmento de publico por setor sem dizer qual setor e recusado');

select is(pg_temp.testa($$
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo, setor_id)
  select w.id, 'a5000000-0000-4000-8000-000000000002', 'setor', s.id
  from public.workspaces w, public.setores s
  where w.slug = 'producao' and s.slug = 'comunicacao'
$$), 'ok',
  'segmento de publico por setor com o setor preenchido e aceito');

select is(pg_temp.testa($$
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo, setor_id, papel)
  select w.id, 'a5000000-0000-4000-8000-000000000002', 'setor', s.id, 'coordenador'
  from public.workspaces w, public.setores s
  where w.slug = 'producao' and s.slug = 'comunicacao'
$$), '23514',
  'segmento de publico com duas colunas de valor preenchidas ao mesmo tempo e recusado');

select is(pg_temp.testa($$
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo, papel)
  select w.id, 'a5000000-0000-4000-8000-000000000002', 'papel', 'chefia'
  from public.workspaces w where w.slug = 'producao'
$$), '23503',
  'segmento de publico por papel so aceita papel que existe no catalogo de papeis');

select is(pg_temp.testa($$
  insert into public.aviso_publicos (workspace_id, aviso_id, tipo, vinculo)
  select w.id, 'a5000000-0000-4000-8000-000000000002', 'vinculo', 'estagiario'
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'segmento de publico por tipo de vinculo so aceita os cinco tipos previstos');

select is(pg_temp.testa($$
  insert into public.aviso_leituras (workspace_id, aviso_id, user_id, versao)
  select w.id, 'a5000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000002', 1
  from public.workspaces w where w.slug = 'producao';
  insert into public.aviso_leituras (workspace_id, aviso_id, user_id, versao)
  select w.id, 'a5000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000002', 1
  from public.workspaces w where w.slug = 'producao'
$$), '23505',
  'a mesma pessoa nao tem duas leituras da mesma versao do mesmo aviso');

select is(pg_temp.testa($$
  insert into public.aviso_leituras (workspace_id, aviso_id, user_id, versao, confirmado_em)
  select w.id, 'a5000000-0000-4000-8000-000000000001', 'b0000000-0000-4000-8000-000000000003', 1, now()
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'ninguem confirma um aviso que nunca chegou a ser visto');

select is(pg_temp.testa($$
  insert into public.grupos (workspace_id, tipo, setor_id, slug, nome, dono_id, criado_por)
  select w.id, 'setor', s.id, 'saude-2', 'Outro mural da Saude',
         'c0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001'
  from public.workspaces w, public.setores s
  where w.slug = 'producao' and s.slug = 'saude'
$$), '23505',
  'cada setor tem um mural so, e o segundo grupo de setor e recusado');

select is(pg_temp.testa($$
  insert into public.grupos (workspace_id, tipo, setor_id, slug, nome, dono_id, criado_por)
  select w.id, 'geral', null, 'geral-2', 'Outro mural geral',
         'ad000000-0000-4000-8000-000000000005', 'ad000000-0000-4000-8000-000000000005'
  from public.workspaces w where w.slug = 'producao'
$$), '23505',
  'o mural geral e um so, e o segundo grupo geral e recusado');

select is(pg_temp.testa($$
  insert into public.grupos (workspace_id, tipo, setor_id, slug, nome, dono_id, criado_por)
  select w.id, 'geral', s.id, 'geral-com-setor', 'Mural geral com setor',
         'ad000000-0000-4000-8000-000000000005', 'ad000000-0000-4000-8000-000000000005'
  from public.workspaces w, public.setores s
  where w.slug = 'producao' and s.slug = 'saude'
$$), '23514',
  'o mural geral nao pertence a setor nenhum');

select is(pg_temp.testa($$
  insert into public.grupos (workspace_id, tipo, setor_id, slug, nome, dono_id, criado_por, fim_previsto)
  select w.id, 'setor', s.id, 'com-prazo', 'Mural com prazo',
         'ad000000-0000-4000-8000-000000000005', 'ad000000-0000-4000-8000-000000000005',
         current_date + 30
  from public.workspaces w, public.setores s
  where w.slug = 'producao' and s.slug = 'comunicacao'
$$), '23514',
  'so grupo de projeto tem data prevista para acabar; mural de setor nao acaba');

select is(pg_temp.testa($$
  update public.grupo_membros set papel = 'owner'
  where grupo_id = '61000000-0000-4000-8000-000000000001'
    and user_id = 'a0000000-0000-4000-8000-000000000002'
$$), '23514',
  'papel de membro de grupo so aceita dono, admin, moderador ou membro, em portugues');

select is(pg_temp.testa($$
  update public.grupo_membros set status = 'membro'
  where grupo_id = '61000000-0000-4000-8000-000000000001'
    and user_id = 'a0000000-0000-4000-8000-000000000002'
$$), '23514',
  'o ciclo de vida do membro so aceita invited, applicant ou member, em ingles');

select is(pg_temp.testa($$
  insert into public.grupo_membros (workspace_id, grupo_id, user_id, papel, status, origem)
  select w.id, '61000000-0000-4000-8000-000000000001',
         'a0000000-0000-4000-8000-000000000002', 'membro', 'member', 'manual'
  from public.workspaces w where w.slug = 'producao'
$$), '23505',
  'a mesma pessoa nao entra duas vezes no mesmo grupo');

select is(pg_temp.testa($$
  insert into public.comentarios (workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo)
  select w.id, 'aviso', 'a5000000-0000-4000-8000-000000000001',
         '61000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000002',
         repeat('x', 2001)
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'comentario com mais de dois mil caracteres e recusado');

select is(pg_temp.testa($$
  update public.comentarios set status = 'hidden'
  where id = 'cccc0000-0000-4000-8000-000000000001'
$$), '23514',
  'ocultar um comentario sem registrar quem ocultou e por que e recusado');

select is(pg_temp.testa($$
  with resposta as (
    insert into public.comentarios (workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo, parent_id)
    select w.id, 'aviso', 'a5000000-0000-4000-8000-000000000001',
           '61000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001',
           'segundo', 'cccc0000-0000-4000-8000-000000000001'
    from public.workspaces w where w.slug = 'producao'
    returning id, workspace_id
  )
  insert into public.comentarios (workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo, parent_id)
  select r.workspace_id, 'aviso', 'a5000000-0000-4000-8000-000000000001',
         '61000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000002', 'terceiro', r.id
  from resposta r
$$), 'P0001',
  'a conversa do mural tem um nivel de resposta so, e a resposta da resposta e recusada');

select is(pg_temp.testa($$
  insert into public.notifications (workspace_id, user_id, title, tipo)
  select w.id, 'a0000000-0000-4000-8000-000000000002', 'Titulo', 'prazo.vence'
  from public.workspaces w where w.slug = 'producao'
$$), '23514',
  'tipo de notificacao fora do catalogo fechado e recusado');

select is(pg_temp.testa($$
  update public.messages set body = 'texto trocado'
  where id = 'e0000000-0000-4000-8000-000000000001'
$$), 'P0001',
  'o texto de uma mensagem direta enviada nao pode ser reescrito');


-- ===========================================================================
-- 2. Seguranca em nivel de linha
-- ===========================================================================

select is(
  (select coalesce(string_agg(c.relname, ', ' order by c.relname), '')
     from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind = 'r'
      and c.relname = any (array['grupos','grupo_membros','avisos','aviso_publicos',
                                 'aviso_leituras','comentarios','notifications','messages'])
      and not c.relrowsecurity),
  '',
  'nenhuma tabela de contato ou de mural fica sem seguranca em nivel de linha ligada');

select is(
  (select coalesce(string_agg(t.tabela, ', ' order by t.tabela), '')
     from unnest(array['grupos','grupo_membros','avisos','aviso_publicos',
                       'aviso_leituras','comentarios','notifications','messages']) as t(tabela)
    where not exists (
      select 1 from pg_policies p
       where p.schemaname = 'public' and p.tablename = t.tabela)),
  '',
  'toda tabela de contato ou de mural tem ao menos uma policy escrita');

select is(
  (select coalesce(string_agg(t.tabela, ', ' order by t.tabela), '')
     from unnest(array['grupos','grupo_membros','avisos','aviso_publicos',
                       'aviso_leituras','comentarios','notifications','messages']) as t(tabela)
    where not exists (
      select 1 from information_schema.role_table_grants g
       where g.table_schema = 'public' and g.table_name = t.tabela
         and g.grantee = 'authenticated' and g.privilege_type = 'SELECT')),
  '',
  'quem entrou na intranet tem permissao de leitura declarada em cada tabela da area');

select is(
  (select count(*)::text
     from information_schema.role_table_grants g
    where g.table_schema = 'public'
      and g.table_name = any (array['grupos','grupo_membros','avisos','aviso_publicos',
                                    'aviso_leituras','comentarios','notifications','messages'])
      and g.grantee = 'anon'),
  '0',
  'visitante sem sessao nao recebe permissao nenhuma nas tabelas do mural');

select is(
  (select count(*)::text from pg_policies
    where schemaname = 'public' and tablename = 'avisos' and cmd = 'DELETE'),
  '0',
  'nada no mural e apagado pelo cliente, e por isso nao existe policy de exclusao de aviso');

select is(
  (select count(*)::text from pg_policies
    where schemaname = 'public' and tablename = 'aviso_leituras' and cmd = 'DELETE'),
  '0',
  'confirmacao de leitura nao se apaga, e por isso nao existe policy de exclusao de leitura');


-- ===========================================================================
-- 3. Quem enxerga o aviso
-- ===========================================================================

select is(pg_temp.le(:ana, $$select private.aviso_visivel('a5000000-0000-4000-8000-000000000001')$$),
  'true',
  'a voluntaria com vinculo ativo na Saude enxerga o aviso dirigido ao setor dela');

select is(pg_temp.le(:bruno, $$select private.aviso_visivel('a5000000-0000-4000-8000-000000000001')$$),
  'false',
  'quem entrou no mural da Saude mas tem vinculo em outro setor nao enxerga o aviso dirigido a Saude');

select is(pg_temp.le(:fora, $$select private.aviso_visivel('a5000000-0000-4000-8000-000000000001')$$),
  'false',
  'quem esta na intranet mas nao entrou no mural nao enxerga o aviso daquele mural');

select is(pg_temp.le(:ana, $$select count(*) from public.avisos
                             where id = 'a5000000-0000-4000-8000-000000000001'$$),
  '1',
  'a destinataria consegue abrir a linha do aviso que lhe foi dirigido');

select is(pg_temp.le(:bruno, $$select count(*) from public.avisos
                               where id = 'a5000000-0000-4000-8000-000000000001'$$),
  '0',
  'quem esta fora do publico do aviso nem chega a ver que ele existe');

select is(pg_temp.le(:ana, $$select count(*) from public.avisos
                             where id = 'a5000000-0000-4000-8000-000000000002'$$),
  '0',
  'aviso em rascunho nao aparece para o destinatario comum');

select is(pg_temp.le(:coord, $$select count(*) from public.avisos
                               where id = 'a5000000-0000-4000-8000-000000000002'$$),
  '1',
  'aviso em rascunho aparece para a dona do mural, que e quem pode moderar');

select is(pg_temp.le(:adm, $$select count(*) from public.avisos
                             where id = 'a5000000-0000-4000-8000-000000000002'$$),
  '1',
  'aviso em rascunho aparece para quem tem permissao de moderar o mural');

select is(pg_temp.le(:fora, $$select count(*) from public.avisos
                              where id = 'a5000000-0000-4000-8000-000000000002'$$),
  '0',
  'quem nao modera nem escreveu o rascunho nao ve o rascunho de ninguem');

-- ACHADO 1: a visibilidade do aviso confere o estado, mas nunca as datas de
-- vigencia. O aviso abaixo esta publicado com vigencia encerrada ontem e
-- continua aparecendo para a destinataria.
select is(pg_temp.le(:ana, $$select private.aviso_visivel('a5000000-0000-4000-8000-000000000003')$$),
  'false',
  'aviso cuja vigencia terminou ontem nao aparece mais para o destinatario');

select is(pg_temp.le(:ana, $$select count(*) from public.avisos
                             where id = 'a5000000-0000-4000-8000-000000000005'$$),
  '0',
  'aviso que ainda esta sendo escrito para daqui a dez dias nao aparece para o destinatario');

select is(pg_temp.le(:ana, $$select count(*) from public.aviso_publicos
                             where aviso_id = 'a5000000-0000-4000-8000-000000000002'$$),
  '0',
  'o publico de um aviso em rascunho nao vaza para quem nao alcanca o aviso');

select is(pg_temp.linhas(:ana, $$update public.grupos set comentarios = false
                                 where id = '61000000-0000-4000-8000-000000000001'$$),
  '0',
  'a voluntaria nao muda as configuracoes do mural do setor dela');

select is(pg_temp.linhas(:coord, $$update public.grupos set exige_aprovacao_previa = true
                                   where id = '61000000-0000-4000-8000-000000000001'$$),
  '1',
  'a dona do mural muda as configuracoes do proprio mural');

-- ACHADO 2: a policy de moderacao de aviso consulta a propria tabela avisos
-- dentro da checagem de escrita, e o Postgres para com recursao infinita.
-- Com isso nenhuma sessao consegue alterar aviso nenhum.
select is(pg_temp.linhas(:coord, $$update public.avisos set corpo = 'Corpo revisado.'
                                   where id = 'a5000000-0000-4000-8000-000000000002'$$, :aal2),
  '1',
  'a dona do mural edita o corpo do rascunho do proprio mural');


-- ===========================================================================
-- 4. Publicacao do aviso
-- ===========================================================================

select is(pg_temp.como(:ana,
  $$select public.publicar_aviso('a5000000-0000-4000-8000-000000000004')$$, :aal2),
  'P0001',
  'quem nao pode publicar no setor do mural nao publica o aviso, mesmo com segundo fator');

select is(pg_temp.como(:coord,
  $$select public.publicar_aviso('a5000000-0000-4000-8000-000000000004')$$),
  'P0001',
  'a coordenadora sem segundo fator verificado na sessao nao publica o aviso');

select is(pg_temp.le(:coord,
  $$select public.publicar_aviso('a5000000-0000-4000-8000-000000000004')$$, :aal2),
  '4',
  'a coordenadora publica e o aviso alcanca os quatro membros do mural');

select is((select status from public.avisos where id = :a_obrig),
  'published',
  'depois da publicacao o aviso passa a publicado');

select isnt((select publicado_em from public.avisos where id = :a_obrig), null,
  'a publicacao carimba a data em que o aviso saiu');

select is((select count(*)::text from public.aviso_leituras
            where aviso_id = :a_obrig and obrigatoria),
  '4',
  'a publicacao congela uma pendencia de leitura obrigatoria por destinatario');

select is((select count(*)::text from public.aviso_leituras
            where aviso_id = :a_obrig and setor_id is null),
  '0',
  'cada pendencia guarda o setor que a pessoa tinha no instante da publicacao');

select is((select count(distinct setor_id)::text from public.aviso_leituras
            where aviso_id = :a_obrig),
  '2',
  'a foto dos destinatarios separa os dois setores alcancados pelo aviso');

select is((select count(*)::text from public.notifications
            where entidade_id = :a_obrig and tipo = 'aviso.leitura_obrigatoria'),
  '4',
  'na mesma transacao cada destinatario recebe a notificacao de leitura obrigatoria');

select is((select count(*)::text from operacao.fila_emails where entidade_id = :a_obrig),
  '4',
  'na mesma transacao cada notificacao entra na fila de e-mail, para nao haver aviso sem entrega');

select is(pg_temp.como(:coord,
  $$select public.publicar_aviso('a5000000-0000-4000-8000-000000000004')$$, :aal2),
  'P0001',
  'aviso ja publicado nao e publicado de novo');

-- ACHADO 3: a publicacao nao olha a vigencia. O aviso abaixo so vale daqui a
-- dez dias e, pelo escopo, deveria ficar agendado ate la.
select is(pg_temp.le(:coord,
  $$select public.publicar_aviso('a5000000-0000-4000-8000-000000000005')$$, :aal2),
  '4',
  'sem segmento de publico, o aviso alcanca todos os membros do mural');

select is((select status from public.avisos where id = :a_agendado),
  'scheduled',
  'aviso cuja vigencia so comeca daqui a dez dias fica agendado, e nao publicado na hora');


-- ===========================================================================
-- 5. Confirmacao de leitura
-- ===========================================================================

select is(pg_temp.como(:ana,
  $$insert into public.aviso_leituras (workspace_id, aviso_id, user_id, obrigatoria, versao, visto_em)
    values ($$ || :ws_lit || $$, 'a5000000-0000-4000-8000-000000000001',
            'a0000000-0000-4000-8000-000000000002', true, 1, now())$$),
  '42501',
  'ninguem cria para si uma leitura marcada como obrigatoria, que e o que fabricaria a taxa do relatorio');

select is(pg_temp.como(:ana,
  $$insert into public.aviso_leituras (workspace_id, aviso_id, user_id, obrigatoria, versao, visto_em)
    values ($$ || :ws_lit || $$, 'a5000000-0000-4000-8000-000000000001',
            'a0000000-0000-4000-8000-000000000002', false, 1, now())$$),
  'ok',
  'a leitura voluntaria da propria pessoa e aceita');

select is(pg_temp.como(:ana,
  $$insert into public.aviso_leituras (workspace_id, aviso_id, user_id, obrigatoria, versao, visto_em)
    values ($$ || :ws_lit || $$, 'a5000000-0000-4000-8000-000000000001',
            'b0000000-0000-4000-8000-000000000003', false, 1, now())$$),
  '42501',
  'ninguem registra leitura em nome de outra pessoa');

select is(pg_temp.como(:bruno,
  $$insert into public.aviso_leituras (workspace_id, aviso_id, user_id, obrigatoria, versao, visto_em)
    values ($$ || :ws_lit || $$, 'a5000000-0000-4000-8000-000000000001',
            'b0000000-0000-4000-8000-000000000003', false, 1, now())$$),
  '42501',
  'quem esta fora do publico do aviso nao registra leitura dele');

-- Ana confirma a propria leitura do aviso obrigatorio, e a confirmacao fica.
set local role authenticated;
set local request.jwt.claim.sub = 'a0000000-0000-4000-8000-000000000002';
update public.aviso_leituras
   set visto_em = now(), confirmado_em = now(), origem_abertura = 'whatsapp'
 where aviso_id = 'a5000000-0000-4000-8000-000000000004'
   and user_id  = 'a0000000-0000-4000-8000-000000000002';
reset role;

select isnt((select confirmado_em from public.aviso_leituras
              where aviso_id = :a_obrig and user_id = :ana), null,
  'a pessoa confirma a propria leitura sem precisar de segundo fator');

select is((select origem_abertura from public.aviso_leituras
            where aviso_id = :a_obrig and user_id = :ana),
  'whatsapp',
  'a confirmacao guarda que a pessoa abriu o aviso pelo link do WhatsApp');

select is(pg_temp.linhas(:ana,
  $$update public.aviso_leituras set visto_em = now(), confirmado_em = now()
    where aviso_id = 'a5000000-0000-4000-8000-000000000004'
      and user_id  = 'b0000000-0000-4000-8000-000000000003'$$),
  '0',
  'o comando de confirmacao de uma pessoa nao alcanca a pendencia de leitura do colega');

select is((select confirmado_em from public.aviso_leituras
            where aviso_id = :a_obrig and user_id = :bruno)::text, null,
  'a pendencia do colega continua sem confirmacao depois da tentativa alheia');

select is(pg_temp.testa($$
  update public.aviso_leituras set confirmado_em = null
  where aviso_id = 'a5000000-0000-4000-8000-000000000004'
    and user_id  = 'a0000000-0000-4000-8000-000000000002'
$$), 'P0001',
  'ciencia de aviso nao se retira, e a confirmacao ja gravada nao volta a nulo');

select is(pg_temp.testa($$
  update public.aviso_leituras set visto_em = null
  where aviso_id = 'a5000000-0000-4000-8000-000000000004'
    and user_id  = 'a0000000-0000-4000-8000-000000000002'
$$), 'P0001',
  'aviso ja aberto nao volta a constar como nao aberto');

select is(pg_temp.testa($$
  update public.aviso_leituras set obrigatoria = false
  where aviso_id = 'a5000000-0000-4000-8000-000000000004'
    and user_id  = 'a0000000-0000-4000-8000-000000000002'
$$), 'P0001',
  'a foto dos destinatarios tirada na publicacao nao e reescrita depois');

select is(pg_temp.le(:ana, $$select count(*) from public.aviso_leituras
                             where aviso_id = 'a5000000-0000-4000-8000-000000000004'$$),
  '1',
  'a voluntaria enxerga apenas a propria pendencia de leitura, e nao a dos colegas');


-- ===========================================================================
-- 6. Relatorio de leitura
-- ===========================================================================

select is(pg_temp.le(:coord, $$select count(*) from public.relatorio_leitura_aviso(
                                'a5000000-0000-4000-8000-000000000004')$$),
  '3',
  'a dona do mural le o relatorio do aviso, com uma linha por setor mais o total');

select is(pg_temp.le(:coord, $$select destinatarios from public.relatorio_leitura_aviso(
                                'a5000000-0000-4000-8000-000000000004') where setor_id is null$$),
  '4',
  'o total do relatorio conta os quatro destinatarios congelados na publicacao');

select is(pg_temp.le(:coord, $$select confirmados from public.relatorio_leitura_aviso(
                                'a5000000-0000-4000-8000-000000000004') where setor_id is null$$),
  '1',
  'o relatorio conta a unica confirmacao ja registrada');

select is(pg_temp.le(:coord, $$select percentual from public.relatorio_leitura_aviso(
                                'a5000000-0000-4000-8000-000000000004') where setor_id is null$$),
  '25.0',
  'o relatorio mostra o percentual de confirmacao, e nao so a contagem');

select is(pg_temp.como(:ana, $$select * from public.relatorio_leitura_aviso(
                                'a5000000-0000-4000-8000-000000000004')$$),
  'P0001',
  'a voluntaria destinataria do aviso nao le o relatorio de leitura do mural');

-- ACHADO 4: o teste de permissao do relatorio soma tres condicoes com "ou", e
-- uma delas devolve nulo para quem nao e membro do grupo. Nulo nao e falso, e
-- a recusa nunca dispara para quem esta de fora.
select is(pg_temp.como(:fora, $$select * from public.relatorio_leitura_aviso(
                                 'a5000000-0000-4000-8000-000000000004')$$),
  'P0001',
  'quem nao entrou no mural nem tem permissao de relatorio no setor nao le o relatorio');

select is(pg_temp.le(:coord, $$select count(*) from public.aviso_leituras
                               where aviso_id = 'a5000000-0000-4000-8000-000000000004'$$),
  '1',
  'a coordenadora ve o relatorio em numero, mas nao a lista nominal de quem falta confirmar');

select is(pg_temp.le(:adm, $$select count(*) from public.aviso_leituras
                             where aviso_id = 'a5000000-0000-4000-8000-000000000004'$$),
  '4',
  'a administradora enxerga a lista nominal do aviso de seguranca operacional');

-- ACHADO 5: pelo escopo a lista nominal cabe a secretaria e a administracao. A
-- policy exige, alem de ver dado restrito, papel no mural ou permissao de
-- relatorio no setor, e o seed nao da nenhuma das duas a secretaria.
select is(pg_temp.le(:sec, $$select count(*) from public.aviso_leituras
                             where aviso_id = 'a5000000-0000-4000-8000-000000000004'$$),
  '4',
  'a secretaria enxerga a lista nominal do aviso de seguranca operacional');


-- ===========================================================================
-- 7. Mensagem direta
-- ===========================================================================

select is(pg_temp.le(:ana, $$select count(*) from public.messages
                             where id = 'e0000000-0000-4000-8000-000000000001'$$),
  '1',
  'quem escreveu a mensagem direta continua lendo a propria conversa');

select is(pg_temp.le(:coord, $$select count(*) from public.messages
                               where id = 'e0000000-0000-4000-8000-000000000001'$$),
  '1',
  'a destinataria le a mensagem direta que lhe foi enviada');

select is(pg_temp.le(:bruno, $$select count(*) from public.messages
                               where id = 'e0000000-0000-4000-8000-000000000001'$$),
  '0',
  'colega de espaco que nao e remetente nem destinatario nao le a conversa');

select is(pg_temp.le(:adm, $$select count(*) from public.messages
                             where id = 'e0000000-0000-4000-8000-000000000001'$$),
  '0',
  'nem a administradora da intranet le a conversa direta de duas pessoas');

select is(pg_temp.le(:sec, $$select count(*) from public.messages
                             where id = 'e0000000-0000-4000-8000-000000000001'$$),
  '0',
  'nem a secretaria le a conversa direta de duas pessoas');

select is(pg_temp.como(:bruno,
  $$insert into public.messages (workspace_id, author_id, recipient_id, body)
    values ($$ || :ws_lit || $$, 'a0000000-0000-4000-8000-000000000002',
            'c0000000-0000-4000-8000-000000000001', 'mensagem forjada')$$),
  '42501',
  'ninguem envia mensagem direta assinando o nome de outra pessoa');

select is(pg_temp.linhas(:coord,
  $$update public.messages set lido_em = now()
    where id = 'e0000000-0000-4000-8000-000000000001'$$),
  '1',
  'a destinataria marca como lida a mensagem que recebeu');


-- ===========================================================================
-- 8. Comentarios e notificacoes
-- ===========================================================================

select is(pg_temp.le(:ana, $$select count(*) from public.comentarios
                             where entidade_id = 'a5000000-0000-4000-8000-000000000001'$$),
  '1',
  'quem esta no publico do aviso le os comentarios daquele aviso');

select is(pg_temp.le(:bruno, $$select count(*) from public.comentarios
                               where entidade_id = 'a5000000-0000-4000-8000-000000000001'$$),
  '0',
  'quem esta fora do publico do aviso nao le os comentarios daquele aviso');

select is(pg_temp.como(:ana,
  $$insert into public.comentarios (workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo, status)
    values ($$ || :ws_lit || $$, 'aviso', 'a5000000-0000-4000-8000-000000000001',
            '61000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000002',
            'Combinado, obrigada.', 'pending')$$),
  'ok',
  'com moderacao ligada no mural, o comentario da voluntaria nasce aguardando aprovacao');

select is(pg_temp.como(:ana,
  $$insert into public.comentarios (workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo, status)
    values ($$ || :ws_lit || $$, 'aviso', 'a5000000-0000-4000-8000-000000000001',
            '61000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000002',
            'Ja aprovado por mim mesma.', 'approved')$$),
  '42501',
  'ninguem publica comentario ja aprovado num mural que exige moderacao');

select is(pg_temp.como(:fora,
  $$insert into public.comentarios (workspace_id, entidade_tipo, entidade_id, grupo_id, autor_id, corpo, status)
    values ($$ || :ws_lit || $$, 'aviso', 'a5000000-0000-4000-8000-000000000001',
            '61000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000006',
            'Passando para comentar.', 'pending')$$),
  '42501',
  'quem nao entrou no mural nao comenta nele');

select is(pg_temp.linhas(:coord,
  $$update public.comentarios
       set status = 'approved', moderado_por = 'c0000000-0000-4000-8000-000000000001',
           moderado_em = now()
     where id = 'cccc0000-0000-4000-8000-000000000001'$$),
  '1',
  'a dona do mural modera o comentario do proprio mural');

select is(pg_temp.linhas(:bruno,
  $$update public.comentarios
       set status = 'hidden', moderado_por = 'b0000000-0000-4000-8000-000000000003',
           moderado_em = now(), motivo = 'nao gostei'
     where id = 'cccc0000-0000-4000-8000-000000000001'$$),
  '0',
  'membro comum do mural nao esconde o comentario de outra pessoa');

select is(pg_temp.como(:ana,
  $$insert into public.notifications (workspace_id, user_id, title, tipo, entidade_tipo, entidade_id)
    values ($$ || :ws_lit || $$, 'b0000000-0000-4000-8000-000000000003', 'Olha o aviso',
            'aviso.publicado', 'aviso', 'a5000000-0000-4000-8000-000000000001')$$),
  '42501',
  'nenhuma tela escreve no sino de outra pessoa: notificar terceiro so por funcao nomeada');

select is(pg_temp.como(:ana,
  $$insert into public.notifications (workspace_id, user_id, title, tipo, entidade_tipo, entidade_id)
    values ($$ || :ws_lit || $$, 'a0000000-0000-4000-8000-000000000002', 'Meu lembrete',
            'aviso.publicado', 'aviso', 'a5000000-0000-4000-8000-000000000001')$$),
  'ok',
  'a acao escreve no sino em nome de quem age, e so dele');

select is(pg_temp.le(:ana, $$select count(*) from public.notifications
                             where entidade_id = 'a5000000-0000-4000-8000-000000000004'$$),
  '1',
  'cada pessoa ve no sino apenas as proprias notificacoes');

select is(pg_temp.le(:bruno, $$select count(*) from public.notifications
                               where entidade_id = 'a5000000-0000-4000-8000-000000000004'$$),
  '1',
  'o colega tambem so ve a propria notificacao do mesmo aviso');


select * from finish();

rollback;


-- ============================================================
-- 03. Biblioteca de documentos, classificacao, retencao e modelos
-- ============================================================

-- ---------------------------------------------------------------------------
-- Testes pgTAP da fase 3: biblioteca de documentos da intranet da CVB-RJ.
--
-- Cobre a arvore de pastas com caminho materializado, as permissoes com
-- heranca e papel local, os documentos, as versoes, os tipos documentais, os
-- niveis de acesso, a retencao e os modelos.
--
-- O bloco mais importante e o do nivel sigiloso: a critica adversarial achou
-- que o documento sigiloso era lido por heranca por qualquer revisor de pasta,
-- ao contrario do que a secao 9.3 do escopo promete. Os testes do bloco D
-- provam que isso nao acontece mais.
--
-- Um teste fica vermelho de proposito e esta marcado no corpo com a palavra
-- ACHADO: e a falha do modelo em deixar conceder a credencial nominal do
-- documento sigiloso, exigida pela secao 17.2 do escopo.
--
-- Como rodar:
--   psql -h /pgtest/sock -U postgres -d t_biblioteca -f testes-03-biblioteca.sql
-- ---------------------------------------------------------------------------

begin;

select plan(92);

-- ---------------------------------------------------------------------------
-- Preparacao: pessoas, papeis, pastas e documentos de teste.
-- A carga roda como superusuario, fora das policies, para que o cenario nao
-- dependa daquilo que os testes ainda vao verificar.
-- ---------------------------------------------------------------------------

select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '', true);

create temp table ids (chave text primary key, valor uuid) on commit drop;
grant select on ids to public;

create function pg_temp.i(text) returns uuid language sql stable as
  $$ select valor from ids where chave = $1 $$;

insert into ids (chave, valor) values
  ('ws',        (select id from public.workspaces where slug = 'producao')),
  ('saude',     (select id from public.setores where slug = 'saude')),
  ('comunic',   (select id from public.setores where slug = 'comunicacao')),
  ('p_saude',   (select id from public.pastas where path = '/setores/saude')),
  ('p_proced',  (select id from public.pastas where path = '/setores/saude/procedimentos')),
  ('p_setores', (select id from public.pastas where path = '/setores')),
  ('p_instit',  (select id from public.pastas where path = '/institucional')),
  ('p_contas',  (select id from public.pastas where path = '/institucional/prestacao-de-contas')),
  ('p_atas',    (select id from public.pastas where path = '/institucional/atas')),
  ('t_relat',   (select id from public.tipos_documentais where tipo_ato = 'relatorio')),
  ('t_contas',  (select id from public.tipos_documentais where tipo_ato = 'prestacao_contas')),
  ('t_ata',     (select id from public.tipos_documentais where tipo_ato = 'ata_diretoria')),
  ('t_termo',   (select id from public.tipos_documentais where tipo_ato = 'termo_adesao')),
  -- pessoas
  ('coord',     '11111111-1111-4111-8111-111111111111'),
  ('colab',     '22222222-2222-4222-8222-222222222222'),
  ('diretor',   '33333333-3333-4333-8333-333333333333'),
  ('vol',       '44444444-4444-4444-8444-444444444444'),
  -- pastas criadas por este teste
  ('a0',        'aaaaaaa0-0000-4000-8000-000000000000'),
  ('a1',        'aaaaaaa1-0000-4000-8000-000000000000'),
  ('a2',        'aaaaaaa2-0000-4000-8000-000000000000'),
  ('a3',        'aaaaaaa3-0000-4000-8000-000000000000'),
  ('destino',   'aaaaaaa4-0000-4000-8000-000000000000'),
  ('p_corte',   'aaaaaaa5-0000-4000-8000-000000000000'),
  ('p_negar',   'aaaaaaa6-0000-4000-8000-000000000000'),
  -- documentos
  ('doc_sig',   'ddddddd1-0000-4000-8000-000000000000'),
  ('doc_rest',  'ddddddd2-0000-4000-8000-000000000000'),
  ('doc_sig_i', 'ddddddd3-0000-4000-8000-000000000000'),
  ('doc_contas','ddddddd4-0000-4000-8000-000000000000'),
  ('doc_ata',   'ddddddd5-0000-4000-8000-000000000000'),
  ('doc_colab', 'ddddddd6-0000-4000-8000-000000000000'),
  ('doc_coord', 'ddddddd8-0000-4000-8000-000000000000'),
  ('v1',        'eeeeeee1-0000-4000-8000-000000000000'),
  ('v2',        'eeeeeee2-0000-4000-8000-000000000000');

insert into auth.users (id) values
  (pg_temp.i('coord')), (pg_temp.i('colab')), (pg_temp.i('diretor')), (pg_temp.i('vol'));

insert into public.profiles (id, username, full_name, initials, tipo_conta) values
  (pg_temp.i('coord'),   'coord.saude', 'Coordenadora da Saude',     'CS', 'equipe'),
  (pg_temp.i('colab'),   'colab.saude', 'Colaborador da Saude',      'LS', 'equipe'),
  (pg_temp.i('diretor'), 'dir.geral',   'Membro da Diretoria',       'MD', 'equipe'),
  (pg_temp.i('vol'),     'vol.comunic', 'Voluntario da Comunicacao', 'VC', 'voluntario');

insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado) values
  (pg_temp.i('ws'), pg_temp.i('coord'),   pg_temp.i('saude'),   'colaborador', 'active'),
  (pg_temp.i('ws'), pg_temp.i('colab'),   pg_temp.i('saude'),   'colaborador', 'active'),
  (pg_temp.i('ws'), pg_temp.i('diretor'), null,                 'diretoria',   'active'),
  (pg_temp.i('ws'), pg_temp.i('vol'),     pg_temp.i('comunic'), 'voluntario',  'active');

insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id) values
  (pg_temp.i('ws'), pg_temp.i('coord'),   'coordenador', pg_temp.i('saude')),
  (pg_temp.i('ws'), pg_temp.i('diretor'), 'diretoria',   null),
  (pg_temp.i('ws'), pg_temp.i('vol'),     'voluntario',  null);

-- Arvore de teste: uma pasta de segundo nivel com tres niveis abaixo dela,
-- exatamente o desenho que a secao 9.1 manda exercitar.
insert into public.pastas (id, workspace_id, parent_id, nome, slug, setor_id, criado_por) values
  (pg_temp.i('a0'), pg_temp.i('ws'), pg_temp.i('p_setores'), 'Arvore',  'arvore',  pg_temp.i('saude'), pg_temp.i('coord')),
  (pg_temp.i('a1'), pg_temp.i('ws'), pg_temp.i('a0'),        'Nivel 1', 'n1',      pg_temp.i('saude'), pg_temp.i('coord')),
  (pg_temp.i('a2'), pg_temp.i('ws'), pg_temp.i('a1'),        'Nivel 2', 'n2',      pg_temp.i('saude'), pg_temp.i('coord')),
  (pg_temp.i('a3'), pg_temp.i('ws'), pg_temp.i('a2'),        'Nivel 3', 'n3',      pg_temp.i('saude'), pg_temp.i('coord')),
  (pg_temp.i('destino'), pg_temp.i('ws'), pg_temp.i('p_setores'), 'Destino', 'destino', pg_temp.i('saude'), pg_temp.i('coord')),
  (pg_temp.i('p_corte'), pg_temp.i('ws'), pg_temp.i('p_proced'), 'Sem heranca', 'sem-heranca', pg_temp.i('saude'), pg_temp.i('coord')),
  (pg_temp.i('p_negar'), pg_temp.i('ws'), pg_temp.i('p_proced'), 'Com negativa', 'com-negativa', pg_temp.i('saude'), pg_temp.i('coord'));

update public.pastas set herda_permissoes = false where id = pg_temp.i('p_corte');

-- Regras de permissao do cenario.
insert into public.pasta_permissoes (pasta_id, sujeito_tipo, sujeito_usuario_id, papel_local, efeito, concedido_por) values
  -- ancestral mais proximo: o colaborador e contribuidor em /setores/saude pela
  -- regra de setor do seed, mas vira leitor de /setores/saude/procedimentos.
  (pg_temp.i('p_proced'), 'usuario', pg_temp.i('colab'), 'leitor', 'permitir', pg_temp.i('coord')),
  -- na arvore de teste ele e editor, para provar a preservacao apos mover.
  (pg_temp.i('a0'),       'usuario', pg_temp.i('colab'), 'editor', 'permitir', pg_temp.i('coord')),
  -- negar vence permitir no mesmo nivel: a concessao nominal e a negativa do
  -- setor convivem na mesma pasta porque sao sujeitos de tipos diferentes.
  (pg_temp.i('p_negar'),  'usuario', pg_temp.i('colab'), 'editor', 'permitir', pg_temp.i('coord'));

insert into public.pasta_permissoes (pasta_id, sujeito_tipo, sujeito_setor_id, papel_local, efeito, concedido_por)
values (pg_temp.i('p_negar'), 'setor', pg_temp.i('saude'), 'editor', 'negar', pg_temp.i('coord'));

-- Documentos do cenario.
insert into public.documentos (id, workspace_id, pasta_id, tipo_documental_id, titulo,
                               nivel_acesso, hipotese_legal, status, criado_por, metadados, data_referencia) values
  (pg_temp.i('doc_sig'), pg_temp.i('ws'), pg_temp.i('p_proced'), pg_temp.i('t_relat'),
   'Relatorio sigiloso de atendimento', 'sigiloso', 'dados_sensiveis_lgpd_art11', 'current',
   pg_temp.i('coord'), '{"setor":"saude","periodo":"2026-01","autor":"Coordenadora"}'::jsonb, current_date),
  (pg_temp.i('doc_rest'), pg_temp.i('ws'), pg_temp.i('p_proced'), pg_temp.i('t_relat'),
   'Relatorio restrito de atendimento', 'restrito', 'dados_sensiveis_lgpd_art11', 'current',
   pg_temp.i('coord'), '{"setor":"saude","periodo":"2026-02","autor":"Coordenadora"}'::jsonb, current_date),
  (pg_temp.i('doc_sig_i'), pg_temp.i('ws'), pg_temp.i('p_instit'), pg_temp.i('t_relat'),
   'Relatorio sigiloso institucional', 'sigiloso', 'deliberacao_diretoria_em_curso', 'current',
   pg_temp.i('coord'), '{"setor":"diretoria","periodo":"2026-01","autor":"Coordenadora"}'::jsonb, current_date),
  (pg_temp.i('doc_contas'), pg_temp.i('ws'), pg_temp.i('p_contas'), pg_temp.i('t_contas'),
   'Prestacao de contas 2026', 'restrito', 'dados_pessoais_lgpd_art7', 'current',
   pg_temp.i('diretor'),
   '{"parceria":"Termo 01","periodo":"2026","valor":"1000","orgao_destinatario":"Prefeitura"}'::jsonb, current_date),
  (pg_temp.i('doc_ata'), pg_temp.i('ws'), pg_temp.i('p_atas'), pg_temp.i('t_ata'),
   'Ata da Diretoria de janeiro', 'restrito', 'dados_pessoais_lgpd_art7', 'current',
   pg_temp.i('diretor'),
   '{"numero":"1","data_reuniao":"2026-01-10","presentes":"todos","pauta":"orcamento"}'::jsonb, current_date),
  (pg_temp.i('doc_colab'), pg_temp.i('ws'), pg_temp.i('p_saude'), pg_temp.i('t_relat'),
   'Relatorio do colaborador', 'restrito', 'dados_sensiveis_lgpd_art11', 'current',
   pg_temp.i('colab'), '{"setor":"saude","periodo":"2026-03","autor":"Colaborador"}'::jsonb, current_date),
  (pg_temp.i('doc_coord'), pg_temp.i('ws'), pg_temp.i('p_saude'), pg_temp.i('t_relat'),
   'Relatorio da coordenadora', 'restrito', 'dados_sensiveis_lgpd_art11', 'current',
   pg_temp.i('coord'), '{"setor":"saude","periodo":"2026-07","autor":"Coordenadora"}'::jsonb, current_date);

insert into public.documento_versoes (id, documento_id, content_type, size_bytes, hash_sha256, enviado_por, storage_path) values
  (pg_temp.i('v1'), pg_temp.i('doc_sig'),  'application/pdf', 2048, repeat('a', 64), pg_temp.i('coord'), 'workspaces/x/biblioteca/a.pdf'),
  (pg_temp.i('v2'), pg_temp.i('doc_rest'), 'application/pdf', 4096, repeat('b', 64), pg_temp.i('coord'), 'workspaces/x/biblioteca/b.pdf');

insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, enviado_por, storage_path) values
  (pg_temp.i('doc_colab'), 'application/pdf', 512, repeat('c', 64), pg_temp.i('colab'), 'workspaces/x/biblioteca/c.pdf'),
  (pg_temp.i('doc_coord'), 'application/pdf', 640, repeat('9', 64), pg_temp.i('coord'), 'workspaces/x/biblioteca/d.pdf');

-- Credencial nominal ja concedida sobre o sigiloso institucional, gravada aqui
-- pela carga porque o proprio modelo nao deixa concede-la pela policy: e o
-- achado que o teste marcado como ACHADO adiante deixa a descoberto.
insert into public.pasta_permissoes (pasta_id, documento_id, sujeito_tipo, sujeito_usuario_id, papel_local, motivo, concedido_por)
values (pg_temp.i('p_instit'), pg_temp.i('doc_sig_i'), 'usuario', pg_temp.i('coord'), 'leitor',
        'credencial nominal para a auditoria do caso', pg_temp.i('diretor'));

-- ---------------------------------------------------------------------------
-- Bloco A: estrutura. As tabelas, colunas e restricoes que a biblioteca exige.
-- ---------------------------------------------------------------------------

select has_table('public', 'pastas',            'A arvore de pastas da biblioteca existe como tabela');
select has_table('public', 'pasta_permissoes',  'As permissoes de pasta e de documento existem como tabela');
select has_table('public', 'documentos',        'O documento, que e o registro logico, existe como tabela');
select has_table('public', 'documento_versoes', 'As versoes do documento existem como tabela');
select has_table('public', 'tipos_documentais', 'A tabela de temporalidade dos tipos documentais existe');
select has_table('public', 'hipoteses_legais',  'O vocabulario de hipoteses legais tem tabela propria');
select has_table('public', 'documento_links',   'Os links internos de documento existem como tabela');
select has_table('public', 'modelos_documento', 'Os modelos de documento existem como tabela');

select has_column('public', 'pastas', 'path',
  'A pasta guarda o caminho materializado, que e o que resolve a heranca');
select has_column('public', 'pastas', 'herda_permissoes',
  'A pasta diz se soma as regras dos ancestrais ou se corta a heranca');
select has_column('public', 'pastas', 'setor_id',
  'A pasta pertence a um setor, e nunca a uma pessoa');
select has_column('public', 'pasta_permissoes', 'papel_local',
  'A regra de permissao guarda o papel local, e nao o papel institucional');
select has_column('public', 'documentos', 'nivel_acesso',
  'O documento guarda o nivel de acesso do vocabulario do SEI');
select has_column('public', 'documentos', 'hipotese_legal',
  'O documento guarda a hipotese legal que justifica a restricao');
select has_column('public', 'documento_versoes', 'hash_sha256',
  'Cada versao guarda o hash SHA-256 do arquivo');

select col_not_null('public', 'documento_versoes', 'hash_sha256',
  'Versao sem hash nao entra: a coluna do hash e obrigatoria');
select col_not_null('public', 'pastas', 'path',
  'Pasta sem caminho materializado nao entra');

select has_index('public', 'documento_versoes', 'documento_versoes_documento_id_primaria_idx',
  'Existe indice que garante uma unica versao vigente por documento');
select has_unique('public', 'pastas',
  'O caminho da pasta e unico dentro do mesmo espaco de trabalho');

select throws_ok(
  $$ insert into public.pasta_permissoes (pasta_id, sujeito_tipo, sujeito_usuario_id, papel_local, concedido_por)
     values (pg_temp.i('p_saude'), 'usuario', pg_temp.i('vol'), 'dono', pg_temp.i('coord')) $$,
  '23514',
  null,
  'Papel local so aceita leitor, contribuidor, editor e revisor');

select throws_ok(
  $$ insert into public.pasta_permissoes (pasta_id, sujeito_tipo, sujeito_usuario_id, sujeito_setor_id, papel_local, concedido_por)
     values (pg_temp.i('p_saude'), 'usuario', pg_temp.i('vol'), pg_temp.i('saude'), 'leitor', pg_temp.i('coord')) $$,
  '23514',
  null,
  'A regra aponta um unico sujeito: pessoa, setor ou papel, nunca dois ao mesmo tempo');

select throws_ok(
  $$ update public.documentos set nivel_acesso = 'secretissimo' where id = pg_temp.i('doc_rest') $$,
  '23514',
  null,
  'Nivel de acesso so aceita publico, restrito e sigiloso');

select throws_ok(
  $$ insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, enviado_por)
     values (pg_temp.i('doc_rest'), 'application/pdf', 10, 'nao-e-um-hash', pg_temp.i('coord')) $$,
  '23514',
  null,
  'Hash que nao e hexadecimal de 64 caracteres e recusado');

select throws_ok(
  $$ insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, enviado_por)
     values (pg_temp.i('doc_rest'), 'application/pdf', 10, null, pg_temp.i('coord')) $$,
  '23502',
  null,
  'Versao com hash nulo e recusada pelo banco');

select throws_ok(
  $$ update public.documentos set hipotese_legal = 'hipotese_inventada' where id = pg_temp.i('doc_rest') $$,
  '23503',
  null,
  'A hipotese legal precisa existir no vocabulario do proprio espaco');

-- ---------------------------------------------------------------------------
-- Bloco B: RLS ligada e policies existentes.
-- ---------------------------------------------------------------------------

-- A area e o conjunto nomeado mais toda tabela que aponte para pasta,
-- documento, versao ou tipo documental. Assim, tabela nova da biblioteca cai
-- neste teste sem que ninguem precise lembrar de incluir o nome aqui.
select is_empty(
  $$ with area as (
       select c.oid, c.relname, c.relrowsecurity
         from pg_class c
         join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
          and c.relkind = 'r'
          and (c.relname in ('pastas','pasta_permissoes','documentos','documento_versoes',
                             'tipos_documentais','hipoteses_legais','documento_links','modelos_documento')
               or exists (
                 select 1
                   from pg_constraint fk
                   join pg_class alvo on alvo.oid = fk.confrelid
                  where fk.conrelid = c.oid
                    and fk.contype = 'f'
                    and alvo.relname in ('pastas','documentos','documento_versoes','tipos_documentais')))
     )
     select relname from area where not relrowsecurity $$,
  'Nenhuma tabela da biblioteca fica sem seguranca de linha ligada');

select is_empty(
  $$ select c.relname
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
        and c.relname in ('pastas','pasta_permissoes','documentos','documento_versoes',
                          'tipos_documentais','hipoteses_legais','documento_links','modelos_documento')
        and not exists (select 1 from pg_policy p where p.polrelid = c.oid) $$,
  'Toda tabela da biblioteca tem ao menos uma regra de acesso escrita');

select is_empty(
  $$ select 'documentos' where not exists (
       select 1 from pg_policy p
       join pg_class c on c.oid = p.polrelid
       join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public' and c.relname = 'documentos' and p.polcmd = 'r') $$,
  'O documento tem regra propria para quem pode ler');

select is_empty(
  $$ select 'anon' from information_schema.role_table_grants
      where table_schema = 'public'
        and table_name in ('documentos','documento_versoes','pastas','pasta_permissoes')
        and grantee = 'anon' $$,
  'Visitante sem sessao nao recebe nenhum acesso as tabelas da biblioteca');

-- ---------------------------------------------------------------------------
-- Bloco C: heranca de permissao e papel local.
-- ---------------------------------------------------------------------------

set local role authenticated;
set local request.jwt.claims = '{"aal":"aal2"}';
set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';

select is(
  private.papel_na_pasta(pg_temp.i('p_saude')), 'contribuidor',
  'Colaborador da Saude contribui na pasta do proprio setor so pela regra de setor, sem regra nominal');

select is(
  private.papel_na_pasta(pg_temp.i('p_proced')), 'leitor',
  'Quando ha regra em pasta mais funda, e ela que vale: na subpasta o colaborador so le');

select is(
  private.papel_na_pasta(pg_temp.i('a3')), 'editor',
  'Papel concedido na pasta de segundo nivel chega ao neto de tres niveis abaixo');

select is(
  private.papel_na_pasta(pg_temp.i('p_negar')), null,
  'Negar vence permitir no mesmo nivel: com as duas regras a pessoa fica sem papel');

select is(
  private.papel_na_pasta(pg_temp.i('p_corte')), null,
  'Pasta que corta a heranca deixa de aproveitar as regras dos ancestrais');

select lives_ok(
  $$ insert into public.documentos (workspace_id, pasta_id, tipo_documental_id, titulo, status, criado_por, metadados)
     values (pg_temp.i('ws'), pg_temp.i('p_saude'), pg_temp.i('t_relat'), 'Relatorio enviado pelo setor',
             'draft', pg_temp.i('colab'), '{"setor":"saude","periodo":"2026-04","autor":"Colaborador"}'::jsonb) $$,
  'Colaborador do setor Saude envia documento na pasta do proprio setor sem precisar de regra nominal');

set local request.jwt.claim.sub = '44444444-4444-4444-8444-444444444444';

select is(
  private.papel_na_pasta(pg_temp.i('p_saude')), null,
  'Voluntario de outro setor nao ganha papel nenhum na pasta da Saude');

select is(
  (select count(*) from public.documentos where pasta_id = pg_temp.i('p_proced'))::int, 0,
  'Voluntario de outro setor nao lista os documentos da pasta da Saude');

-- A recusa chega pela policy da tabela, e nao pelo gatilho de validacao. Os
-- gatilhos de validacao sao security definer de proposito (senao a primeira
-- credencial nominal do sigiloso nunca poderia ser concedida), entao eles
-- enxergam a pasta e passam adiante; quem barra e a policy, que roda sobre a
-- sessao real. Erro esperado: 42501, violacao de policy.
select throws_ok(
  $$ insert into public.documentos (workspace_id, pasta_id, tipo_documental_id, titulo, status, criado_por, metadados)
     values (pg_temp.i('ws'), pg_temp.i('p_saude'), pg_temp.i('t_relat'), 'Relatorio de intruso',
             'draft', pg_temp.i('vol'), '{"setor":"saude","periodo":"2026-05","autor":"Intruso"}'::jsonb) $$,
  '42501',
  null,
  'Voluntario de outro setor nao consegue enviar documento para a pasta da Saude');

set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';

select is(
  private.papel_na_pasta(pg_temp.i('p_saude')), 'revisor',
  'Coordenadora com papel no setor Saude e revisora da raiz do proprio setor');

set local request.jwt.claim.sub = '33333333-3333-4333-8333-333333333333';

select is(
  private.papel_na_pasta(pg_temp.i('p_saude')), 'leitor',
  'Membro da Diretoria apenas le nas pastas de setor, e nao revisa');

select is(
  private.papel_na_pasta(pg_temp.i('p_instit')), 'revisor',
  'Membro da Diretoria revisa a pasta institucional, que e a dele');

reset role;

-- Regra do proprio documento vence a regra da pasta.
insert into public.pasta_permissoes (pasta_id, documento_id, sujeito_tipo, sujeito_usuario_id, papel_local, efeito, motivo, concedido_por)
values (pg_temp.i('p_proced'), pg_temp.i('doc_rest'), 'usuario', pg_temp.i('colab'), 'editor', 'permitir',
        'excecao pontual para revisar este relatorio', pg_temp.i('coord'));

set local role authenticated;
set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';

select is(
  private.papel_na_pasta(pg_temp.i('p_proced')), 'leitor',
  'A regra do documento nao muda o papel da pessoa na pasta inteira');

select is(
  private.papel_no_documento(pg_temp.i('doc_rest')), 'editor',
  'Regra escrita para o proprio documento vence a regra herdada da pasta');

select is(
  private.papel_no_documento(pg_temp.i('doc_colab')), 'contribuidor',
  'Sem regra propria, o documento segue o papel que a pessoa tem na pasta');

reset role;

-- ---------------------------------------------------------------------------
-- Bloco D: o nivel sigiloso. Este e o ponto que a critica adversarial abriu.
-- Papel local na pasta nao abre documento sigiloso: e preciso credencial
-- nominal no proprio documento e sessao com segundo fator verificado.
-- ---------------------------------------------------------------------------

set local role authenticated;
set local request.jwt.claims = '{"aal":"aal2"}';
set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';

select is(
  private.papel_no_documento(pg_temp.i('doc_sig')), null,
  'Revisora da pasta nao ganha papel nenhum sobre o documento sigiloso que esta nela');

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_sig'))::int, 0,
  'Revisora da pasta, com segundo fator e sem credencial nominal, nao le o documento sigiloso');

select is(
  (select count(*) from public.documento_versoes where documento_id = pg_temp.i('doc_sig'))::int, 0,
  'Sem credencial nominal ninguem alcanca o arquivo nem o texto extraido do sigiloso');

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_rest'))::int, 1,
  'O corte vale so para o sigiloso: o documento restrito da mesma pasta continua legivel por heranca');

select ok(
  private.pode_classificar_documento(pg_temp.i('doc_sig')),
  'Quem revisa a pasta continua podendo reclassificar o sigiloso, mesmo sem poder abri-lo');

set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_sig'))::int, 0,
  'Colaborador da Saude com papel na pasta nao le o documento sigiloso');

set local request.jwt.claim.sub = '44444444-4444-4444-8444-444444444444';

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_sig'))::int, 0,
  'Voluntario de fora do setor nao le o documento sigiloso');

set local request.jwt.claim.sub = '33333333-3333-4333-8333-333333333333';

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_sig_i'))::int, 0,
  'Membro da Diretoria, com segundo fator e sem credencial nominal, recebe zero linhas no sigiloso da pasta que ele revisa');

-- Controle positivo: em documento que a pessoa alcanca, conceder a regra
-- nominal do proprio documento funciona.
select lives_ok(
  $$ insert into public.pasta_permissoes (pasta_id, documento_id, sujeito_tipo, sujeito_usuario_id, papel_local, motivo, concedido_por)
     values (pg_temp.i('p_contas'), pg_temp.i('doc_contas'), 'usuario', pg_temp.i('colab'), 'leitor',
             'acesso pontual para conferencia da prestacao', pg_temp.i('diretor')) $$,
  'Quem revisa a pasta escreve regra nominal para o documento restrito que ela alcanca');

-- ACHADO. A secao 17.2 do escopo exige que quem nao le o sigiloso continue
-- podendo conceder a credencial nominal dele. Hoje nao consegue: o gatilho
-- public.pasta_permissoes_herda_espaco le public.documentos sem ser security
-- definer, entao a linha do documento sigiloso nao aparece nem para quem a
-- policy de insercao autoriza, e a primeira credencial nunca sai. O teste fica
-- vermelho de proposito, para registrar a falha do modelo.
select lives_ok(
  $$ insert into public.pasta_permissoes (pasta_id, documento_id, sujeito_tipo, sujeito_usuario_id, papel_local, motivo, concedido_por)
     values (pg_temp.i('p_instit'), pg_temp.i('doc_sig_i'), 'usuario', pg_temp.i('colab'), 'leitor',
             'credencial nominal para a auditoria do caso', pg_temp.i('diretor')) $$,
  'Quem revisa a pasta, sem ler o sigiloso, continua podendo conceder a credencial nominal a outra pessoa');

set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_sig_i'))::int, 1,
  'Com credencial nominal e sessao de segundo fator, a pessoa passa a ler o documento sigiloso');

set local request.jwt.claims = '{"aal":"aal1"}';

select is(
  (select count(*) from public.documentos where id = pg_temp.i('doc_sig_i'))::int, 0,
  'A mesma pessoa, com a credencial nominal mas sem o segundo fator na sessao, volta a nao ler o sigiloso');

reset role;

select throws_ok(
  $$ insert into public.documento_links (documento_id, slug, expira_em, criado_por)
     values (pg_temp.i('doc_sig_i'), 'abcdefghijklmnopqrstuvwxyz', now() + interval '7 days', pg_temp.i('diretor')) $$,
  'P0001',
  'link interno nunca e emitido para documento sigiloso',
  'Documento sigiloso nunca recebe link interno de compartilhamento');

-- ---------------------------------------------------------------------------
-- Bloco E: versoes. Uma so vigente por documento, hash obrigatorio e promocao
-- que rebaixa a anterior na mesma transacao.
-- ---------------------------------------------------------------------------

select is(
  (select count(*) from public.documento_versoes where documento_id = pg_temp.i('doc_rest') and is_primary)::int, 1,
  'Documento recem-criado ja tem exatamente uma versao vigente');

select is(
  (select numero from public.documento_versoes where id = pg_temp.i('v2'))::int, 1,
  'A primeira versao de um documento recebe o numero 1');

select throws_ok(
  $$ insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, is_primary, enviado_por)
     values (pg_temp.i('doc_rest'), 'application/pdf', 100, repeat('d', 64), true, pg_temp.i('coord')) $$,
  '23505',
  null,
  'Nao ha como gravar uma segunda versao vigente do mesmo documento');

set local role authenticated;
set local request.jwt.claims = '{"aal":"aal2"}';
set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';

select lives_ok(
  $$ insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, motivo, enviado_por)
     values (pg_temp.i('doc_rest'), 'application/pdf', 8192, repeat('e', 64), 'correcao do anexo', pg_temp.i('coord')) $$,
  'Revisora da pasta sobe a versao 2 do documento');

select is(
  (select numero from public.documento_versoes
     where documento_id = pg_temp.i('doc_rest') and hash_sha256 = repeat('e', 64))::int, 2,
  'A versao nova recebe o numero seguinte sem que ninguem informe');

select lives_ok(
  $$ select public.definir_versao_primaria(
       (select id from public.documento_versoes
         where documento_id = pg_temp.i('doc_rest') and hash_sha256 = repeat('e', 64))) $$,
  'Revisora promove a versao 2 a vigente');

select ok(
  (select is_primary from public.documento_versoes
    where documento_id = pg_temp.i('doc_rest') and hash_sha256 = repeat('e', 64)),
  'Depois da promocao a versao 2 e a vigente');

select ok(
  not (select is_primary from public.documento_versoes where id = pg_temp.i('v2')),
  'Na mesma transacao a versao 1 deixa de ser a vigente');

select is(
  (select count(*) from public.documento_versoes where documento_id = pg_temp.i('doc_rest') and is_primary)::int, 1,
  'Depois de promover a versao 2 continua havendo uma unica versao vigente');

select throws_ok(
  $$ update public.documento_versoes set hash_sha256 = repeat('f', 64) where id = pg_temp.i('v2') $$,
  'P0001',
  'versao de documento e imutavel: corrigir e subir nova versao',
  'A versao ja gravada nunca e editada: corrigir e subir versao nova');

set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';

select lives_ok(
  $$ insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, enviado_por)
     values (pg_temp.i('doc_colab'), 'application/pdf', 700, repeat('1', 64), pg_temp.i('colab')) $$,
  'Contribuidor sobe versao nova do documento que ele mesmo criou');

select throws_ok(
  $$ insert into public.documento_versoes (documento_id, content_type, size_bytes, hash_sha256, enviado_por)
     values (pg_temp.i('doc_coord'), 'application/pdf', 700, repeat('2', 64), pg_temp.i('colab')) $$,
  '42501',
  null,
  'Contribuidor e recusado ao tentar versionar documento de outra pessoa');

reset role;

-- ---------------------------------------------------------------------------
-- Bloco F: caminho materializado das pastas.
-- ---------------------------------------------------------------------------

select is(
  (select path from public.pastas where id = pg_temp.i('a3')), '/setores/arvore/n1/n2/n3',
  'A pasta neta nasce com o caminho montado a partir do caminho da mae');

select is(
  (select profundidade from public.pastas where id = pg_temp.i('a3'))::int, 5,
  'A profundidade da pasta neta e contada a partir da raiz');

update public.pastas set slug = 'arvore-nova', nome = 'Arvore renomeada' where id = pg_temp.i('a0');

select is(
  (select path from public.pastas where id = pg_temp.i('a1')), '/setores/arvore-nova/n1',
  'Renomear a pasta reescreve o caminho da filha');

select is(
  (select path from public.pastas where id = pg_temp.i('a3')), '/setores/arvore-nova/n1/n2/n3',
  'Renomear a pasta reescreve tambem o caminho dos tres niveis abaixo dela');

set local role authenticated;
set local request.jwt.claims = '{"aal":"aal2"}';
set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';

select is(
  private.papel_na_pasta(pg_temp.i('a3')), 'editor',
  'Depois de renomear a pasta, o neto devolve o mesmo papel de antes');

reset role;

update public.pastas set parent_id = pg_temp.i('destino') where id = pg_temp.i('a0');

select is(
  (select path from public.pastas where id = pg_temp.i('a3')), '/setores/destino/arvore-nova/n1/n2/n3',
  'Mover a pasta reescreve o caminho de toda a subarvore');

select is(
  (select profundidade from public.pastas where id = pg_temp.i('a3'))::int, 6,
  'Mover a pasta tambem acerta a profundidade dos descendentes');

set local role authenticated;
set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';

select is(
  private.papel_na_pasta(pg_temp.i('a3')), 'editor',
  'Depois de mover a pasta, o neto continua com o mesmo papel');

reset role;

select throws_ok(
  $$ update public.pastas set parent_id = pg_temp.i('a2') where id = pg_temp.i('a0') $$,
  'P0001',
  'pasta nao pode ser movida para dentro da propria subarvore',
  'Pasta nao pode ser movida para dentro da propria subarvore');

select throws_ok(
  $$ update public.pastas set slug = 'outro-nome' where id = pg_temp.i('p_proced') $$,
  'P0001',
  'pasta raiz criada por seed nao pode ser movida nem renomeada',
  'Pasta de setor criada pelo seed nao pode ser renomeada, nem na profundidade tres');

select throws_ok(
  $$ insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, criado_por)
     values (pg_temp.i('ws'), pg_temp.i('a3'), 'Fundo demais', 'fundo', pg_temp.i('saude'), pg_temp.i('coord')) $$,
  'P0001',
  'profundidade maxima da arvore de pastas e de seis niveis',
  'A arvore de pastas para no sexto nivel');

-- ---------------------------------------------------------------------------
-- Bloco G: tipos documentais, niveis de acesso e retencao.
-- ---------------------------------------------------------------------------

select throws_ok(
  $$ insert into public.documentos (workspace_id, pasta_id, tipo_documental_id, titulo, nivel_acesso, status, criado_por, metadados, data_referencia)
     values (pg_temp.i('ws'), pg_temp.i('p_atas'), pg_temp.i('t_ata'), 'Ata publicada por engano',
             'publico', 'draft', pg_temp.i('diretor'),
             '{"numero":"9","data_reuniao":"2026-02-10","presentes":"todos","pauta":"tudo"}'::jsonb, current_date) $$,
  'P0001',
  null,
  'Tipo documental que contem dado pessoal nao aceita documento em nivel publico');

insert into public.documentos (id, workspace_id, pasta_id, tipo_documental_id, titulo, status, criado_por, metadados)
values ('ddddddd7-0000-4000-8000-000000000000', pg_temp.i('ws'), pg_temp.i('p_proced'), pg_temp.i('t_relat'),
        'Relatorio nascido na pasta da Saude', 'draft', pg_temp.i('coord'),
        '{"setor":"saude","periodo":"2026-06","autor":"Coordenadora"}'::jsonb);

select is(
  (select nivel_acesso from public.documentos where id = 'ddddddd7-0000-4000-8000-000000000000'), 'restrito',
  'Documento criado na pasta de setor restrito por padrao nasce restrito, mesmo com tipo publico');

select is(
  (select hipotese_legal from public.documentos where id = 'ddddddd7-0000-4000-8000-000000000000'),
  'dados_sensiveis_lgpd_art11',
  'Na pasta do setor Saude a hipotese legal exigida e a de dados sensiveis');

select is(
  (select nivel_acesso_maximo from public.pastas where id = pg_temp.i('p_proced')), 'sigiloso',
  'A pasta assume o maior nivel de acesso dos documentos que guarda');

select is(
  (select retencao_ate from public.documentos where id = pg_temp.i('doc_contas')),
  (current_date + interval '10 years')::date,
  'A prestacao de contas guarda dez anos contados da data de apresentacao');

select is(
  (select retencao_ate from public.documentos where id = pg_temp.i('doc_rest')), null,
  'Tipo com prazo de guarda ainda a fixar pela Diretoria nao ganha data de retencao');

select is(
  (select retencao_ate from public.documentos where id = pg_temp.i('doc_ata')), null,
  'Tipo de guarda permanente nunca vence e por isso nao tem data de retencao');

set local role authenticated;
set local request.jwt.claims = '{"aal":"aal2"}';
set local request.jwt.claim.sub = '33333333-3333-4333-8333-333333333333';

select throws_ok(
  $$ select public.eliminar_documento(pg_temp.i('doc_contas'), 'pedido de eliminacao para teste') $$,
  'P0001',
  null,
  'Prestacao de contas nao e eliminada antes do fim do prazo de guarda');

select throws_ok(
  $$ select public.eliminar_documento(pg_temp.i('doc_ata'), 'pedido de eliminacao para teste') $$,
  'P0001',
  'tipo documental de guarda permanente nunca e eliminado',
  'Ata de guarda permanente nunca e eliminada');

reset role;

-- ---------------------------------------------------------------------------
-- Bloco H: modelos de documento.
-- ---------------------------------------------------------------------------

select throws_ok(
  $$ insert into public.modelos_documento (workspace_id, slug, nome, tipo_documental_id, corpo, status, criado_por)
     values (pg_temp.i('ws'), 'termo_sem_revisao', 'Termo sem revisao', pg_temp.i('t_termo'),
             'corpo do termo', 'approved', pg_temp.i('diretor')) $$,
  '23514',
  null,
  'Modelo so vai a aprovado com quem revisou e quando revisou registrados');

insert into public.modelos_documento (id, workspace_id, slug, nome, tipo_documental_id, corpo, status, criado_por)
values ('ccccccc1-0000-4000-8000-000000000000', pg_temp.i('ws'), 'termo_adesao', 'Termo de adesao',
        pg_temp.i('t_termo'), 'Eu, {{pessoa.nome_completo}}, adiro ao servico voluntario.', 'draft', pg_temp.i('diretor'));

set local role authenticated;
set local request.jwt.claims = '{"aal":"aal2"}';
set local request.jwt.claim.sub = '44444444-4444-4444-8444-444444444444';

select is(
  (select count(*) from public.modelos_documento where id = 'ccccccc1-0000-4000-8000-000000000000')::int, 0,
  'Voluntario nao enxerga modelo em rascunho escrito por outra pessoa');

set local request.jwt.claim.sub = '33333333-3333-4333-8333-333333333333';

select is(
  (select count(*) from public.modelos_documento where id = 'ccccccc1-0000-4000-8000-000000000000')::int, 1,
  'Quem classifica documento enxerga o modelo em rascunho');

reset role;

select * from finish();

rollback;


-- ============================================================
-- 04. Autorizacao de documentos, assinatura e trilha de auditoria
-- ============================================================

-- ============================================================================
-- Testes pgTAP das fases 4 e 5 da intranet da CVB-RJ
-- Autorizacao de documentos, assinatura e trilha de auditoria
--
-- Roda com:
--   psql -h /pgtest/sock -U postgres -d t_autorizacao -f testes-04-autorizacao.sql
--
-- Tudo acontece dentro de uma transacao que termina em rollback: o banco fica
-- exatamente como estava. As pessoas de teste nascem aqui, e cada cena troca a
-- sessao com "set local role authenticated" mais a claim sub, como faz o
-- PostgREST no Supabase.
--
-- Dois testes reprovam de proposito, e estao juntos na secao 9. Eles nao medem
-- o teste, medem o modelo, e ficam vermelhos ate que a correcao entre:
--
--   92. auditoria.registrar_evento grava com "returning seq". Numa insercao com
--       returning o Postgres tambem aplica a regra de leitura da tabela, e a da
--       trilha so deixa ler quem tem trilha.ler_completa. Resultado: quem nao e
--       auditor, administrador ou encarregado nao consegue gravar o proprio
--       evento, e como toda RPC das fases 4 e 5 passa por esse ajudante, todo o
--       tramite trava para o usuario comum.
--   93. public.abrir_autorizacao grava o pedido com "returning id". A regra de
--       leitura de public.autorizacoes chama private.autorizacao_visivel, que
--       procura o pedido na propria tabela; dentro da mesma instrucao a linha
--       ainda nao existe para essa consulta, a regra devolve falso e a abertura
--       falha para qualquer pessoa, inclusive para quem le a trilha inteira.
-- ============================================================================

-- Saida em TAP puro, do jeito que a integracao continua le com pg_prove.
\set ECHO none
\pset format unaligned
\pset tuples_only true
\pset pager off

begin;

select plan(93);

-- ---------------------------------------------------------------------------
-- Preparo do ambiente que imita o Supabase
-- ---------------------------------------------------------------------------
-- No projeto real o papel authenticated ja tem uso dos schemas auth e
-- extensions. O dump local nao carrega esses grants, entao eles entram aqui;
-- nada disso e do modelo sob teste e tudo volta atras no rollback.
grant usage on schema auth, extensions, storage to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;

create schema teste;
grant usage on schema teste to anon, authenticated, service_role;

create table teste.ref (chave text primary key, valor uuid);
create table teste.resultado (chave text primary key, estado text);
grant select, insert, update on teste.ref, teste.resultado to anon, authenticated, service_role;

-- Executa uma instrucao e devolve "ok" ou o codigo de erro do banco, sem
-- derrubar a transacao. E o que permite medir uma recusa de dentro da sessao
-- de outra pessoa.
create function teste.tentar(p_sql text) returns text
language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then
  return sqlstate;
end;
$$;
grant execute on function teste.tentar(text) to anon, authenticated, service_role;

-- Abre a sessao de alguem: identidade, segundo fator e idade do fator.
create function teste.sessao(p_nome text, p_aal text default 'aal2', p_idade_segundos integer default 0)
returns void language plpgsql as $$
declare v_id uuid := (select valor from teste.ref where chave = p_nome);
begin
  perform set_config('request.jwt.claim.sub', v_id::text, true);
  perform set_config('request.jwt.claims', jsonb_build_object(
    'sub', v_id::text,
    'role', 'authenticated',
    'aal', p_aal,
    'amr', case when p_aal = 'aal2'
             then jsonb_build_array(jsonb_build_object(
                    'method', 'totp',
                    'timestamp', extract(epoch from now() - make_interval(secs => p_idade_segundos))::bigint))
             else jsonb_build_array(jsonb_build_object('method', 'password',
                    'timestamp', extract(epoch from now())::bigint)) end
  )::text, true);
end;
$$;
grant execute on function teste.sessao(text, text, integer) to anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Pessoas
-- ---------------------------------------------------------------------------
-- ana    solicitante comum, colaboradora do setor Humanitario
-- carlos coordenador do setor Humanitario, aprovador da etapa 1
-- diana  Diretoria, homologa a etapa 2
-- bruno  colaborador de outro setor, nao enxerga nem decide
--
-- carlos e diana levam tambem o papel encarregado, que e o unico papel de
-- escrita do catalogo com trilha.ler_completa. Sem ele nenhum deles consegue
-- gravar evento na cadeia, pelo defeito que a secao 9 deste arquivo isola: e
-- concessao de bancada para que as regras do tramite sejam medidas por elas
-- mesmas, e nao pelo defeito.
do $$
declare
  v_ws  uuid := (select id from public.workspaces where kind = 'production' limit 1);
  v_hum uuid := (select id from public.setores where slug = 'humanitario');
  v_grd uuid := (select id from public.setores where slug = 'grd');
  v_id  uuid;
  r     record;
begin
  insert into teste.ref values ('workspace', v_ws), ('setor_humanitario', v_hum), ('setor_grd', v_grd);

  for r in select * from (values
      ('ana',    'colaborador', false, false, 'humanitario'),
      ('carlos', 'coordenador', true,  true,  'humanitario'),
      ('diana',  'diretoria',   false, true,  'humanitario'),
      ('bruno',  'colaborador', false, false, 'grd')
    ) as t(nome, papel, setorial, le_trilha, setor)
  loop
    v_id := gen_random_uuid();
    insert into auth.users (id, email) values (v_id, r.nome || '.teste@exemplo.local');
    update public.profiles set full_name = initcap(r.nome) || ' de Teste' where id = v_id;
    insert into public.workspace_members (workspace_id, user_id, role, coordination)
      values (v_ws, v_id, 'colaborador', r.setor);
    insert into public.vinculos (workspace_id, profile_id, setor_id, tipo, estado)
      values (v_ws, v_id, case when r.setor = 'grd' then v_grd else v_hum end, 'colaborador', 'active');
    insert into public.usuario_papeis (workspace_id, user_id, papel, setor_id)
      values (v_ws, v_id, r.papel, case when r.setorial then v_hum end);
    if r.le_trilha then
      insert into public.usuario_papeis (workspace_id, user_id, papel) values (v_ws, v_id, 'encarregado');
    end if;
    insert into teste.ref values (r.nome, v_id);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Documentos e pedidos usados nas cenas de tramite
-- ---------------------------------------------------------------------------
do $$
declare
  v_ws    uuid := (select valor from teste.ref where chave = 'workspace');
  v_hum   uuid := (select valor from teste.ref where chave = 'setor_humanitario');
  v_ana   uuid := (select valor from teste.ref where chave = 'ana');
  v_carlos uuid := (select valor from teste.ref where chave = 'carlos');
  v_pasta uuid := (select id from public.pastas where path = '/setores/humanitario' limit 1);
  v_tipo  uuid := (select id from public.tipos_documentais where tipo_ato = 'oficio');
  v_regra public.autorizacao_regras%rowtype;
  v_leve  public.autorizacao_regras%rowtype;
  v_doc   uuid;
  v_ver   uuid;
  v_ped   uuid;
  v_etapa uuid;
  r       record;
begin
  select * into v_regra from public.autorizacao_regras where tipo_ato = 'oficio';
  select * into v_leve  from public.autorizacao_regras where tipo_ato = 'participacao_acao';

  -- Tres oficios em tramite: aprovacao, devolucao e arquivo alterado.
  for r in select * from (values
      ('aprovacao', 'aaaaaaaa'), ('devolucao', 'bbbbbbbb'), ('etag', 'cccccccc')
    ) as t(cena, semente)
  loop
    insert into public.documentos (workspace_id, pasta_id, tipo_documental_id, titulo,
                                   metadados, data_referencia, hipotese_legal, criado_por)
    values (v_ws, v_pasta, v_tipo, 'Oficio da cena ' || r.cena,
            jsonb_build_object('destinatario', 'Coordenacao Nacional', 'assunto', 'Teste'),
            current_date, 'dados_pessoais_lgpd_art7', v_ana)
    returning id into v_doc;

    insert into public.documento_versoes (workspace_id, documento_id, is_primary, content_type,
                                          size_bytes, hash_sha256, enviado_por)
    values (v_ws, v_doc, true, 'application/pdf', 2048, repeat(r.semente, 8), v_ana)
    returning id into v_ver;

    insert into public.autorizacoes (workspace_id, tipo, tipo_ato, regra_id, objeto_tipo, objeto_id,
                                     versao_id, hash_arquivo_submissao, rodada, sequencia_do_objeto,
                                     solicitante_id, setor_id, estado, etapa_atual, dados,
                                     tipo_gestao, nivel_assinatura_exigido)
    values (v_ws, 'document', 'oficio', v_regra.id, 'documentos', v_doc, v_ver,
            -- na cena do etag o hash congelado na submissao nao e o da versao
            case when r.cena = 'etag' then repeat('d', 64) else repeat(r.semente, 8) end,
            1, 1, v_ana, v_hum, 'in_review', 1, '{}'::jsonb, 'manual', 'nenhuma')
    returning id into v_ped;

    insert into public.autorizacao_etapas (workspace_id, autorizacao_id, ordem, papel_aprovador,
                                           setor_id, prazo_dias_uteis, estado, aberta_em, prazo_em)
    values (v_ws, v_ped, 1, 'coordenador', v_hum, 5, 'open', now(), now() + interval '5 days')
    returning id into v_etapa;

    insert into public.autorizacao_etapas (workspace_id, autorizacao_id, ordem, papel_aprovador,
                                           setor_id, prazo_dias_uteis, estado)
    values (v_ws, v_ped, 2, 'diretoria', v_hum, 10, 'waiting');

    insert into teste.ref values ('pedido_' || r.cena, v_ped), ('etapa1_' || r.cena, v_etapa),
                                 ('documento_' || r.cena, v_doc), ('versao_' || r.cena, v_ver);
  end loop;

  -- Pedido leve aberto pelo proprio coordenador: e a cena do conflito de interesse.
  insert into public.autorizacoes (workspace_id, tipo, tipo_ato, regra_id, objeto_tipo, objeto_id,
                                   rodada, sequencia_do_objeto, solicitante_id, setor_id, estado,
                                   etapa_atual, dados, tipo_gestao, nivel_assinatura_exigido)
  values (v_ws, 'light', 'participacao_acao', v_leve.id, 'profiles', v_carlos, 1, 1,
          v_carlos, v_hum, 'pending', 1, '{}'::jsonb, 'manual', 'nenhuma')
  returning id into v_ped;
  insert into public.autorizacao_etapas (workspace_id, autorizacao_id, ordem, papel_aprovador,
                                         setor_id, prazo_dias_uteis, estado, aberta_em, prazo_em)
  values (v_ws, v_ped, 1, 'coordenador', v_hum, 5, 'open', now(), now() + interval '5 days');
  insert into teste.ref values ('pedido_proprio', v_ped);

  -- Pedido leve da ana: e a cena da retirada.
  insert into public.autorizacoes (workspace_id, tipo, tipo_ato, regra_id, objeto_tipo, objeto_id,
                                   rodada, sequencia_do_objeto, solicitante_id, setor_id, estado,
                                   etapa_atual, dados, tipo_gestao, nivel_assinatura_exigido)
  values (v_ws, 'light', 'participacao_acao', v_leve.id, 'profiles', v_ana, 1, 1,
          v_ana, v_hum, 'pending', 1, '{}'::jsonb, 'manual', 'nenhuma')
  returning id into v_ped;
  insert into public.autorizacao_etapas (workspace_id, autorizacao_id, ordem, papel_aprovador,
                                         setor_id, prazo_dias_uteis, estado, aberta_em, prazo_em)
  values (v_ws, v_ped, 1, 'coordenador', v_hum, 5, 'open', now(), now() + interval '5 days')
  returning id into v_etapa;
  insert into teste.ref values ('pedido_retirada', v_ped), ('etapa1_retirada', v_etapa);

  -- Assinatura simples ja registrada, para as provas de evidencia imutavel.
  insert into public.assinaturas (workspace_id, autorizacao_id, documento_id, versao_id,
                                  signatario_id, nivel, metodo, estado, hash_arquivo, aal,
                                  ip, user_agent, assinado_em)
  values (v_ws, (select valor from teste.ref where chave = 'pedido_aprovacao'),
          (select valor from teste.ref where chave = 'documento_aprovacao'),
          (select valor from teste.ref where chave = 'versao_aprovacao'),
          v_ana, 'simples', 'totp', 'completed', repeat('a', 64), 'aal2',
          '198.51.100.10'::inet, 'Navegador de teste', now())
  returning id into v_ped;
  insert into teste.ref values ('assinatura', v_ped);
end $$;

-- ============================================================================
-- 1. Estrutura: as tabelas da autorizacao, da assinatura e da trilha existem
-- ============================================================================

select has_table('auditoria', 'eventos',
  'a trilha de auditoria tem tabela propria de eventos');
select has_table('auditoria', 'fluxos',
  'o catalogo de fluxos existe e e o que traduz o codigo neutro dentro do banco');
select has_table('auditoria', 'verificacoes',
  'cada execucao do verificador da cadeia fica registrada em tabela propria');
select has_table('auditoria', 'ancoras',
  'a ancora diaria do hash agregado tem tabela propria');
select has_table('public', 'autorizacoes',
  'o pedido de autorizacao tem tabela propria');
select has_table('public', 'autorizacao_etapas',
  'as etapas copiadas da regra no ato da submissao tem tabela propria');
select has_table('public', 'autorizacao_decisoes',
  'cada decisao tomada no tramite tem linha propria');
select has_table('public', 'autorizacao_regras',
  'a regra que diz quem decide, em quanto tempo e o que acontece ao vencer tem tabela propria');
select has_table('public', 'politicas_assinatura',
  'o nivel de assinatura exigido por tipo de ato vive em tabela propria');
select has_table('public', 'assinaturas',
  'a evidencia de assinatura tem tabela propria');
select has_table('public', 'delegacoes',
  'a delegacao por ausencia tem tabela propria');

select col_not_null('auditoria', 'eventos', 'ordem_no_fluxo',
  'todo evento nasce com o numero de ordem dentro do seu fluxo');
select col_not_null('auditoria', 'eventos', 'hash_anterior',
  'todo evento aponta para o hash do evento anterior do mesmo fluxo');
select col_not_null('auditoria', 'eventos', 'hash_linha',
  'todo evento carrega o proprio hash calculado pelo banco');
select index_is_unique('auditoria', 'eventos', 'eventos_fluxo_ordem_no_fluxo_idx',
  'dois eventos nunca ocupam a mesma posicao dentro de um fluxo');

select col_is_pk('public', 'autorizacoes', 'id',
  'cada pedido de autorizacao e identificado por uma chave so');
select fk_ok('public', 'autorizacao_etapas', 'autorizacao_id', 'public', 'autorizacoes', 'id',
  'a etapa pertence sempre a um pedido existente');
select fk_ok('public', 'autorizacao_decisoes', 'etapa_id', 'public', 'autorizacao_etapas', 'id',
  'a decisao pertence sempre a uma etapa existente');
select fk_ok('public', 'assinaturas', 'autorizacao_id', 'public', 'autorizacoes', 'id',
  'a assinatura pertence sempre a um pedido existente');

-- ============================================================================
-- 2. Estrutura: as restricoes que o escopo promete
-- ============================================================================

select throws_ok($$
  insert into public.autorizacoes (workspace_id, tipo, tipo_ato, regra_id, objeto_tipo, objeto_id,
                                   rodada, sequencia_do_objeto, solicitante_id, setor_id, estado, dados)
  select (select valor from teste.ref where chave='workspace'), 'light', 'participacao_acao', r.id,
         'profiles', (select valor from teste.ref where chave='ana'), 1, 90,
         (select valor from teste.ref where chave='ana'),
         (select valor from teste.ref where chave='setor_humanitario'), 'in_review', '{}'::jsonb
    from public.autorizacao_regras r where r.tipo_ato = 'participacao_acao'
$$, '23514', null,
  'um pedido leve nunca entra num estado que so existe no tramite por documento');

select throws_ok($$
  insert into public.autorizacoes (workspace_id, tipo, tipo_ato, regra_id, objeto_tipo, objeto_id,
                                   rodada, sequencia_do_objeto, solicitante_id, setor_id, estado, dados)
  select (select valor from teste.ref where chave='workspace'), 'light', 'participacao_acao', r.id,
         'profiles', (select valor from teste.ref where chave='ana'), 1, 91,
         (select valor from teste.ref where chave='ana'),
         (select valor from teste.ref where chave='setor_humanitario'), 'denied', '{}'::jsonb
    from public.autorizacao_regras r where r.tipo_ato = 'participacao_acao'
$$, '23514', null,
  'negar um pedido sem escrever o motivo e recusado pelo banco');

select lives_ok($$
  insert into public.autorizacao_decisoes (workspace_id, autorizacao_id, etapa_id, ator_id,
                                           papel_exercido, decisao, hash_decisao)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='pedido_retirada'),
          (select valor from teste.ref where chave='etapa1_retirada'),
          null, 'sistema', 'auto_approved', repeat('e', 64))
$$, 'decisao tomada por decurso de prazo entra sem pessoa e com o papel sistema');

select throws_ok($$
  insert into public.autorizacao_decisoes (workspace_id, autorizacao_id, etapa_id, ator_id,
                                           papel_exercido, decisao, hash_decisao)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='pedido_retirada'),
          (select valor from teste.ref where chave='etapa1_retirada'),
          (select valor from teste.ref where chave='ana'), 'sistema', 'auto_approved', repeat('e', 64))
$$, '23514', null,
  'decisao com o papel sistema nunca aponta para uma pessoa');

select throws_ok($$
  update public.assinaturas
     set conferido_por = signatario_id, conferido_em = now(), resultado_validador = 'aprovado'
   where id = (select valor from teste.ref where chave='assinatura')
$$, '23514', null,
  'quem assinou nunca e quem confere a propria assinatura');

select throws_ok($$
  insert into public.assinaturas (workspace_id, autorizacao_id, signatario_id, nivel, metodo,
                                  estado, hash_arquivo)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'nenhuma', 'totp', 'pending', repeat('a',64))
$$, '23514', null,
  'nao existe assinatura de nivel nenhuma: o ato sem assinatura simplesmente nao gera evidencia');

-- ============================================================================
-- 3. Seguranca por linha ligada em toda tabela da area
-- ============================================================================

select is(
  (select count(*)::int from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname, c.relname) in (
            ('auditoria','eventos'), ('auditoria','fluxos'), ('auditoria','verificacoes'),
            ('auditoria','ancoras'), ('public','autorizacoes'), ('public','autorizacao_etapas'),
            ('public','autorizacao_decisoes'), ('public','autorizacao_regras'),
            ('public','politicas_assinatura'), ('public','delegacoes'), ('public','assinaturas'))
      and c.relkind = 'r'),
  11,
  'as onze tabelas de autorizacao, assinatura e trilha estao todas no banco');

select is(
  (select coalesce(string_agg(n.nspname || '.' || c.relname, ', ' order by c.relname), '')
     from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname, c.relname) in (
            ('auditoria','eventos'), ('auditoria','fluxos'), ('auditoria','verificacoes'),
            ('auditoria','ancoras'), ('public','autorizacoes'), ('public','autorizacao_etapas'),
            ('public','autorizacao_decisoes'), ('public','autorizacao_regras'),
            ('public','politicas_assinatura'), ('public','delegacoes'), ('public','assinaturas'))
      and c.relkind = 'r'
      and not c.relrowsecurity),
  '',
  'nenhuma tabela de autorizacao, assinatura ou trilha fica sem seguranca por linha');

select is(
  (select coalesce(string_agg(n.nspname || '.' || c.relname, ', ' order by c.relname), '')
     from pg_class c
     join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname, c.relname) in (
            ('auditoria','eventos'), ('auditoria','fluxos'), ('auditoria','verificacoes'),
            ('auditoria','ancoras'), ('public','autorizacoes'), ('public','autorizacao_etapas'),
            ('public','autorizacao_decisoes'), ('public','autorizacao_regras'),
            ('public','politicas_assinatura'), ('public','delegacoes'), ('public','assinaturas'))
      and c.relkind = 'r'
      and not exists (select 1 from pg_policy p where p.polrelid = c.oid)),
  '',
  'toda tabela da area tem ao menos uma regra de acesso escrita');

select policies_are('auditoria', 'eventos',
  array['eventos_select_auditor', 'eventos_insert_proprio_ator'],
  'a trilha so aceita leitura de quem audita e insercao em nome proprio, e nada mais');

select is(
  (select count(*)::int from pg_policy p
    where p.polrelid = 'auditoria.eventos'::regclass and p.polcmd in ('w', 'd')),
  0,
  'a trilha nao tem nenhuma regra que permita alterar ou apagar evento');

select is(
  (select count(*)::int
     from information_schema.role_table_grants
    where table_schema = 'auditoria' and table_name = 'eventos'
      and grantee in ('authenticated', 'anon', 'service_role')
      and privilege_type in ('UPDATE', 'DELETE')),
  0,
  'nem o aplicativo nem a chave de servico recebem permissao de alterar ou apagar evento');

-- ============================================================================
-- 4. A cadeia de hashes encadeia na ordem certa
-- ============================================================================

-- Tres eventos no fluxo da autorizacao de imagem, e no meio deles dois eventos
-- de outro fluxo, para que a chave seq fique salteada dentro de cada fluxo.
insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                               acao, depois, hash_anterior, hash_linha)
values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
        (select valor from teste.ref where chave='pedido_aprovacao'),
        (select valor from teste.ref where chave='ana'), 'solicitante',
        'imagem.autorizacao_concedida', '{"estado":"pending"}'::jsonb, repeat('0',64), repeat('0',64));

insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                               acao, hash_anterior, hash_linha)
values ((select valor from teste.ref where chave='workspace'), 'F11', 'profiles',
        (select valor from teste.ref where chave='ana'),
        (select valor from teste.ref where chave='ana'), 'colaborador',
        'titular.exportado', repeat('0',64), repeat('0',64));

insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                               acao, depois, hash_anterior, hash_linha)
values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
        (select valor from teste.ref where chave='pedido_aprovacao'),
        (select valor from teste.ref where chave='carlos'), 'coordenador',
        'imagem.uso_publicado', '{"estado":"approved"}'::jsonb, repeat('0',64), repeat('0',64));

insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                               acao, hash_anterior, hash_linha)
values ((select valor from teste.ref where chave='workspace'), 'F11', 'profiles',
        (select valor from teste.ref where chave='carlos'),
        (select valor from teste.ref where chave='carlos'), 'coordenador',
        'titular.exportado', repeat('0',64), repeat('0',64));

insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                               acao, depois, hash_anterior, hash_linha)
values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
        (select valor from teste.ref where chave='pedido_aprovacao'),
        (select valor from teste.ref where chave='diana'), 'diretoria',
        'imagem.autorizacao_revogada', '{"estado":"archived"}'::jsonb, repeat('0',64), repeat('0',64));

select is(
  (select hash_anterior from auditoria.eventos where fluxo = 'F06' and ordem_no_fluxo = 1),
  repeat('0', 64),
  'o primeiro evento de um fluxo aponta para uma origem de sessenta e quatro zeros');

select results_eq(
  $$ select ordem_no_fluxo from auditoria.eventos where fluxo = 'F06' order by ordem_no_fluxo $$,
  $$ values (1::bigint), (2::bigint), (3::bigint) $$,
  'os eventos de um fluxo recebem numeros de ordem seguidos, comecando em um');

select ok(
  (select max(seq) - min(seq) > 2 from auditoria.eventos where fluxo = 'F06'),
  'a chave sequencial fica salteada quando outro fluxo escreve no meio, e por isso nao ordena a cadeia');

select is(
  (select e2.hash_anterior from auditoria.eventos e1
     join auditoria.eventos e2 on e2.fluxo = e1.fluxo and e2.ordem_no_fluxo = e1.ordem_no_fluxo + 1
    where e1.fluxo = 'F06' and e1.ordem_no_fluxo = 1),
  (select hash_linha from auditoria.eventos where fluxo = 'F06' and ordem_no_fluxo = 1),
  'cada evento amarra o hash do evento imediatamente anterior do mesmo fluxo');

select is(
  (select count(*)::int from auditoria.eventos e
     join auditoria.eventos anterior
       on anterior.fluxo = e.fluxo and anterior.ordem_no_fluxo = e.ordem_no_fluxo - 1
    where e.fluxo in ('F06', 'F11') and e.hash_anterior <> anterior.hash_linha),
  0,
  'nenhum elo da cadeia aponta para um hash que nao seja o do seu antecessor');

select is(
  (select ok from auditoria.verificar_cadeia('F06', 'script')),
  true,
  'depois de gravar eventos o verificador diz que a cadeia esta integra');

select is(
  (select ok from auditoria.verificacoes where fluxo = 'F06' order by id desc limit 1),
  true,
  'a execucao do verificador fica registrada com o resultado integro');

select is(
  (select count(*)::int from auditoria.eventos
    where fluxo = 'F06' and acao = 'auditoria.verificacao_ok'),
  1,
  'a propria verificacao da cadeia entra na cadeia como evento do sistema');

-- Adulteracao por dentro do banco: desliga o guarda append-only, que so o dono
-- do banco consegue desligar, muda o conteudo de um evento e liga de volta.
alter table auditoria.eventos disable trigger eventos_append_only;
update auditoria.eventos
   set depois = '{"estado":"denied"}'::jsonb
 where fluxo = 'F06' and ordem_no_fluxo = 2;
alter table auditoria.eventos enable trigger eventos_append_only;

select is(
  (select ok from auditoria.verificar_cadeia('F06', 'script')),
  false,
  'conteudo de evento trocado por dentro do banco derruba a verificacao da cadeia');

select is(
  (select primeira_quebra_seq from auditoria.verificacoes where fluxo = 'F06' order by id desc limit 1),
  (select seq from auditoria.eventos where fluxo = 'F06' and ordem_no_fluxo = 2),
  'o verificador aponta exatamente o evento adulterado como a primeira quebra');

select is(
  (select ok from auditoria.verificar_cadeia('F11', 'script')),
  true,
  'a quebra de um fluxo nao contamina o resultado dos outros fluxos');

-- ============================================================================
-- 5. Append-only de verdade: update e delete recusados para qualquer papel
-- ============================================================================

insert into teste.resultado values
  ('eventos_antes', (select count(*)::text from auditoria.eventos where fluxo = 'F06'));

select throws_ok($$
  update auditoria.eventos set papel = 'outro' where fluxo = 'F06'
$$, '42501', null,
  'nem o dono do banco altera um evento ja gravado na trilha');

select throws_ok($$
  delete from auditoria.eventos where fluxo = 'F06'
$$, '42501', null,
  'nem o dono do banco apaga um evento ja gravado na trilha');

set local role service_role;
insert into teste.resultado values
  ('servico_update', teste.tentar($$ update auditoria.eventos set papel = 'outro' where fluxo = 'F06' $$)),
  ('servico_delete', teste.tentar($$ delete from auditoria.eventos where fluxo = 'F06' $$));
reset role;

select is((select estado from teste.resultado where chave = 'servico_update'), '42501',
  'a chave de servico, que passa por cima das regras de linha, tambem nao altera evento');
select is((select estado from teste.resultado where chave = 'servico_delete'), '42501',
  'a chave de servico tambem nao apaga evento');

set local role authenticated;
select teste.sessao('diana');
insert into teste.resultado values
  ('app_update', teste.tentar($$ update auditoria.eventos set papel = 'outro' where fluxo = 'F06' $$)),
  ('app_delete', teste.tentar($$ delete from auditoria.eventos where fluxo = 'F06' $$));
reset role;

select is((select estado from teste.resultado where chave = 'app_update'), '42501',
  'quem entra pelo aplicativo, ainda que possa ler a trilha inteira, nao altera evento');
select is((select estado from teste.resultado where chave = 'app_delete'), '42501',
  'quem entra pelo aplicativo nao apaga evento');

set local role anon;
insert into teste.resultado values
  ('anonimo_update', teste.tentar($$ update auditoria.eventos set papel = 'outro' where fluxo = 'F06' $$)),
  ('anonimo_delete', teste.tentar($$ delete from auditoria.eventos where fluxo = 'F06' $$));
reset role;

select is((select estado from teste.resultado where chave = 'anonimo_update'), '42501',
  'visitante sem sessao nao chega perto de alterar evento');
select is((select estado from teste.resultado where chave = 'anonimo_delete'), '42501',
  'visitante sem sessao nao chega perto de apagar evento');

select is(
  (select count(*)::text from auditoria.eventos where fluxo = 'F06'),
  (select estado from teste.resultado where chave = 'eventos_antes'),
  'depois de todas as tentativas de alteracao a trilha continua com os mesmos eventos');

-- ============================================================================
-- 6. Nenhum dado pessoal entra na trilha
-- ============================================================================

select is(
  (select coalesce(string_agg(column_name, ', ' order by column_name), '')
     from information_schema.columns
    where table_schema = 'auditoria' and table_name = 'eventos'
      and column_name ~* '(nome|mail|telefone|celular|cpf|^rg$|endereco|corpo|conteudo|texto|mensagem|motivo|titulo|metadata|arquivo_nome)'),
  '',
  'a trilha nao tem coluna de nome, e-mail, telefone, motivo, corpo de documento nem texto livre');

select has_column('auditoria', 'eventos', 'ator_id',
  'a trilha diz quem agiu por identificador, e nunca por nome');
select has_column('auditoria', 'eventos', 'ip_hash',
  'a trilha guarda a impressao digital do endereco de rede, e nunca o endereco');
select has_column('auditoria', 'eventos', 'user_agent_hash',
  'a trilha guarda a impressao digital do navegador, e nunca o navegador');

select is(
  (select count(*)::int from pg_constraint con
    where con.conrelid = 'auditoria.eventos'::regclass
      and con.contype = 'f'
      and 'ator_id' = (select a.attname from pg_attribute a
                        where a.attrelid = con.conrelid and a.attnum = con.conkey[1])),
  0,
  'quem agiu fica como identificador solto, para que apagar a pessoa nao viole a trilha');

select throws_ok($$
  insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                                 acao, ip_hash, hash_anterior, hash_linha)
  values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'solicitante',
          'imagem.uso_publicado', '198.51.100.10', repeat('0',64), repeat('0',64))
$$, '23514', null,
  'endereco de rede em claro nao cabe na coluna de impressao digital da trilha');

select throws_ok($$
  insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                                 acao, depois, hash_anterior, hash_linha)
  values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'solicitante',
          'imagem.uso_publicado', '{"nome":"Ana de Teste"}'::jsonb, repeat('0',64), repeat('0',64))
$$, '42501', null,
  'gravar o nome de alguem no antes ou no depois do evento e recusado pelo banco');

select throws_ok($$
  insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                                 acao, antes, hash_anterior, hash_linha)
  values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'solicitante',
          'imagem.uso_publicado', '{"email":"ana@exemplo.org"}'::jsonb, repeat('0',64), repeat('0',64))
$$, '42501', null,
  'gravar o e-mail de alguem no antes ou no depois do evento e recusado pelo banco');

select throws_ok($$
  insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                                 acao, depois, hash_anterior, hash_linha)
  values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'solicitante',
          'imagem.uso_publicado', '{"motivo":"pedido negado por falta de verba"}'::jsonb,
          repeat('0',64), repeat('0',64))
$$, '42501', null,
  'o motivo escrito por uma pessoa fica na decisao, que e apagavel, e nunca na trilha');

select lives_ok($$
  insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                                 acao, depois, hash_anterior, hash_linha)
  values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'solicitante',
          'imagem.uso_publicado', '{"estado":"approved","rodada":1}'::jsonb,
          repeat('0',64), repeat('0',64))
$$, 'estado e rodada, que sao fatos do tramite e nao da pessoa, entram no evento sem problema');

select throws_ok($$
  insert into auditoria.eventos (workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel,
                                 acao, hash_anterior, hash_linha)
  values ((select valor from teste.ref where chave='workspace'), 'F06', 'autorizacoes',
          (select valor from teste.ref where chave='pedido_aprovacao'),
          (select valor from teste.ref where chave='ana'), 'solicitante',
          'mural.aviso_publicado', repeat('0',64), repeat('0',64))
$$, '23514', null,
  'acao fora do vocabulario fechado da trilha nao entra sem migracao que altere a lista');

-- A ponte da Redacao com o catalogo de fluxos vazio: a Redacao continua
-- trabalhando e a falha da trilha fica contada na tela de operacao.
delete from lgpd.operacoes where fluxo_codigo = 'F09';
delete from auditoria.fluxos where codigo = 'F09';

select lives_ok($$
  insert into public.activity_log (workspace_id, actor_id, action, entity_type, entity_id, metadata)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='ana'), 'published', 'content_pieces',
          (select valor from teste.ref where chave='pedido_devolucao'), '{}'::jsonb)
$$, 'com o catalogo de fluxos vazio a Redacao continua gravando a propria trilha sem erro');

select is(
  (select valor::int from operacao.uso_plano
    where metrica = 'ponte_auditoria_falhou' and dia = current_date),
  1,
  'a falha da ponte para a cadeia aparece contada na tela de operacao');

-- Com o catalogo de volta, a ponte copia o fato e nunca o campo livre.
insert into auditoria.fluxos (codigo, nome_interno, descricao)
values ('F09', 'editorial', 'Ponte do activity_log da Redacao.');

insert into public.activity_log (workspace_id, actor_id, action, entity_type, entity_id, metadata)
values ((select valor from teste.ref where chave='workspace'),
        (select valor from teste.ref where chave='ana'), 'published', 'content_pieces',
        (select valor from teste.ref where chave='pedido_aprovacao'),
        '{"nome":"Ana de Teste","email":"ana@exemplo.org","corpo":"texto da materia"}'::jsonb);

select is(
  (select depois from auditoria.eventos where fluxo = 'F09' order by seq desc limit 1),
  '{"estado": "published"}'::jsonb,
  'a ponte da Redacao leva para a cadeia so o fato, e deixa para tras o campo livre com dado pessoal');

select is(
  (select count(*)::int from auditoria.eventos
    where fluxo = 'F09' and (coalesce(antes::text,'') || coalesce(depois::text,'')) ~* '(ana|exemplo\.org|materia)'),
  0,
  'nenhum evento vindo da Redacao carrega nome, e-mail ou trecho de conteudo');

-- ============================================================================
-- 7. O tramite: quem decide, quem nao decide e o que a decisao move
-- ============================================================================

-- Quem esta fora do setor nem enxerga o pedido.
set local role authenticated;
select teste.sessao('bruno');
insert into teste.resultado values ('bruno_decide', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_aprovacao'), 'approved', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'bruno_decide'), 'P0002',
  'colaborador de outro setor nem enxerga o pedido, quanto mais decide');

-- Quem enxerga mas nao exerce o papel da etapa aberta tambem nao decide.
set local role authenticated;
select teste.sessao('diana');
insert into teste.resultado values ('diana_decide_etapa1', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_aprovacao'), 'approved', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'diana_decide_etapa1'), '42501',
  'a Diretoria enxerga o pedido, mas nao decide a etapa que e da coordenacao');

-- Ninguem decide o proprio pedido.
set local role authenticated;
select teste.sessao('carlos');
insert into teste.resultado values ('carlos_proprio', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_proprio'), 'approved', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'carlos_proprio'), '42501',
  'o coordenador exerce o papel da etapa, mas nao aprova o pedido que ele mesmo abriu');

-- Sessao sem segundo fator nao decide.
set local role authenticated;
select teste.sessao('carlos', 'aal1');
insert into teste.resultado values ('carlos_sem_fator', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_etag'), 'approved', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'carlos_sem_fator'), '42501',
  'decidir sem segundo fator verificado e recusado');

-- Segundo fator verificado ha dezesseis minutos ja nao vale.
set local role authenticated;
select teste.sessao('carlos', 'aal2', 960);
insert into teste.resultado values ('carlos_fator_velho', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_etag'), 'approved', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'carlos_fator_velho'), '42501',
  'segundo fator verificado ha dezesseis minutos nao serve para decidir');

-- Arquivo alterado depois da submissao nao se decide.
set local role authenticated;
select teste.sessao('carlos');
insert into teste.resultado values ('carlos_etag', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_etag'), 'approved', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'carlos_etag'), '40001',
  'ninguem decide sobre arquivo que mudou depois da submissao');

-- A aprovacao da etapa 1 move o pedido na mesma transacao.
set local role authenticated;
select teste.sessao('carlos');
insert into teste.resultado values ('carlos_aprova', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_aprovacao'), 'approved', null,
    repeat('a', 64), '198.51.100.20'::inet, 'Navegador de teste')
$$));
reset role;

select is((select estado from teste.resultado where chave = 'carlos_aprova'), 'ok',
  'o coordenador do setor de origem aprova a etapa da coordenacao');

select is(
  (select estado from public.autorizacoes where id = (select valor from teste.ref where chave='pedido_aprovacao')),
  'in_validation',
  'aprovada a etapa da coordenacao, o pedido sai de em analise e vai para homologacao');

select results_eq(
  $$ select ordem, estado from public.autorizacao_etapas
      where autorizacao_id = (select valor from teste.ref where chave='pedido_aprovacao') order by ordem $$,
  $$ values (1::smallint, 'approved'), (2::smallint, 'open') $$,
  'a etapa decidida fecha e a etapa seguinte abre na mesma transacao');

select is(
  (select count(*)::int from public.autorizacao_decisoes
    where autorizacao_id = (select valor from teste.ref where chave='pedido_aprovacao')
      and decisao = 'approved'
      and ator_id = (select valor from teste.ref where chave='carlos')),
  1,
  'a decisao fica registrada com quem decidiu e com o que foi decidido');

select is(
  (select count(*)::int from auditoria.eventos
    where entidade_id = (select valor from teste.ref where chave='pedido_aprovacao')
      and acao = 'autorizacao.aprovada'),
  1,
  'a aprovacao deixa o seu evento na trilha, na mesma transacao da decisao');

-- A devolucao leva o pedido a mudancas pedidas.
set local role authenticated;
select teste.sessao('carlos');
insert into teste.resultado values ('carlos_devolve', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_devolucao'), 'returned',
    'Falta o numero do processo no cabecalho.', repeat('b', 64))
$$));
reset role;

select is((select estado from teste.resultado where chave = 'carlos_devolve'), 'ok',
  'o aprovador da etapa aberta devolve o documento com motivo escrito');

select is(
  (select estado from public.autorizacoes where id = (select valor from teste.ref where chave='pedido_devolucao')),
  'changes_requested',
  'a devolucao leva o pedido para mudancas pedidas');

set local role authenticated;
select teste.sessao('carlos');
insert into teste.resultado values ('devolve_sem_motivo', teste.tentar($$
  select public.decidir_autorizacao(
    (select valor from teste.ref where chave='pedido_etag'), 'returned', null, null)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'devolve_sem_motivo'), '22023',
  'devolver sem escrever o motivo e recusado');

-- Invariante do sistema: pedido em analise ou em homologacao sempre tem etapa aberta.
select is(
  (select count(*)::int from public.autorizacoes a
    where a.estado in ('in_review', 'in_validation')
      and not exists (select 1 from public.autorizacao_etapas e
                       where e.autorizacao_id = a.id and e.estado = 'open')),
  0,
  'nao existe pedido em analise ou em homologacao sem etapa aberta esperando alguem');

-- Retirada: cabe so ao solicitante e nao exige segundo fator.
set local role authenticated;
select teste.sessao('ana', 'aal1');
insert into teste.resultado values ('ana_retira', teste.tentar($$
  insert into public.autorizacao_decisoes (workspace_id, autorizacao_id, etapa_id, ator_id,
                                           papel_exercido, decisao, hash_decisao)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='pedido_retirada'),
          (select valor from teste.ref where chave='etapa1_retirada'),
          (select auth.uid()), 'solicitante', 'withdrawn',
          public.hash_canonico('{"decisao":"withdrawn"}'::jsonb))
$$));
reset role;

select is((select estado from teste.resultado where chave = 'ana_retira'), 'ok',
  'a voluntaria sem segundo fator retira o proprio pedido leve');

set local role authenticated;
select teste.sessao('bruno', 'aal1');
insert into teste.resultado values ('bruno_retira', teste.tentar($$
  insert into public.autorizacao_decisoes (workspace_id, autorizacao_id, etapa_id, ator_id,
                                           papel_exercido, decisao, hash_decisao)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='pedido_retirada'),
          (select valor from teste.ref where chave='etapa1_retirada'),
          (select auth.uid()), 'solicitante', 'withdrawn',
          public.hash_canonico('{"decisao":"withdrawn"}'::jsonb))
$$));
reset role;

select is((select estado from teste.resultado where chave = 'bruno_retira'), '42501',
  'ninguem retira o pedido de outra pessoa');

-- ============================================================================
-- 8. Assinatura: a evidencia gravada nao muda depois
-- ============================================================================

select throws_ok($$
  update public.assinaturas set hash_arquivo = repeat('f', 64)
   where id = (select valor from teste.ref where chave='assinatura')
$$, '42501', null,
  'o hash do arquivo assinado nunca muda depois de gravado');

select throws_ok($$
  update public.assinaturas set nivel = 'avancada'
   where id = (select valor from teste.ref where chave='assinatura')
$$, '42501', null,
  'o nivel da assinatura nunca muda depois de gravado');

select throws_ok($$
  update public.assinaturas set metodo = 'govbr'
   where id = (select valor from teste.ref where chave='assinatura')
$$, '42501', null,
  'o metodo da assinatura nunca muda depois de gravado');

select throws_ok($$
  update public.assinaturas set signatario_id = (select valor from teste.ref where chave='carlos')
   where id = (select valor from teste.ref where chave='assinatura')
$$, '42501', null,
  'quem assinou nunca e trocado por outra pessoa');

select throws_ok($$
  update public.assinaturas set codigo_verificacao = 'ABCDEFGHJKMNPQRSTVWXYZ0123'
   where id = (select valor from teste.ref where chave='assinatura')
$$, '42501', null,
  'o codigo da pagina publica de conferencia nunca muda depois de gerado');

select lives_ok($$
  update public.assinaturas
     set resultado_validador = 'aprovado', hash_confere = true,
         conferido_por = (select valor from teste.ref where chave='carlos'), conferido_em = now()
   where id = (select valor from teste.ref where chave='assinatura')
$$, 'a conferencia posterior por outra pessoa entra sem tocar na evidencia da assinatura');

-- O proprio signatario nao reabre a evidencia pelo aplicativo.
set local role authenticated;
select teste.sessao('ana');
insert into teste.resultado values ('ana_altera_assinatura', teste.tentar($$
  update public.assinaturas set estado = 'pending', assinado_em = null
   where id = (select valor from teste.ref where chave='assinatura')
$$));
reset role;

select is(
  (select estado from public.assinaturas where id = (select valor from teste.ref where chave='assinatura')),
  'completed',
  'depois de concluida a assinatura, nem o proprio signatario a reabre pelo aplicativo');

select throws_ok($$
  insert into public.assinaturas (workspace_id, autorizacao_id, signatario_id, nivel, metodo,
                                  estado, hash_arquivo)
  values ((select valor from teste.ref where chave='workspace'),
          (select valor from teste.ref where chave='pedido_devolucao'),
          (select valor from teste.ref where chave='ana'), 'avancada', 'govbr', 'completed', repeat('a',64))
$$, '23514', null,
  'assinatura no gov.br nao fica concluida sem o hash conferido e o parecer do validador');

-- ============================================================================
-- 9. Achados: o que o modelo ainda nao entrega
-- ============================================================================
-- Os dois testes abaixo falham de proposito. Eles nao medem o teste, medem o
-- modelo: as duas escritas sao o comeco de todo caminho das fases 4 e 5.

set local role authenticated;
select teste.sessao('ana');
insert into teste.resultado values ('evento_colaborador', teste.tentar($$
  select auditoria.registrar_evento(
    (select valor from teste.ref where chave='workspace'), 'F02', 'autorizacoes',
    (select valor from teste.ref where chave='pedido_retirada'),
    'autorizacao.solicitada', 'solicitante')
$$));
reset role;

select is((select estado from teste.resultado where chave = 'evento_colaborador'), 'ok',
  'uma colaboradora comum consegue gravar o proprio evento na trilha');

set local role authenticated;
select teste.sessao('ana');
insert into teste.resultado values ('abrir_pedido', teste.tentar($$
  select public.abrir_autorizacao('participacao_acao'::public.tipo_ato, 'profiles',
    (select valor from teste.ref where chave='bruno'),
    (select valor from teste.ref where chave='setor_humanitario'), '{}'::jsonb)
$$));
reset role;

select is((select estado from teste.resultado where chave = 'abrir_pedido'), 'ok',
  'a solicitante abre um pedido leve pela funcao de abertura do tramite');

select * from finish();
rollback;
