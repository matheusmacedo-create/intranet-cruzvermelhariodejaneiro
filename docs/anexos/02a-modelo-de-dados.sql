-- Modelo de dados da intranet da CVB-RJ
-- Anexo 02a do escopo (docs/02-escopo.md). Postgres 17 no Supabase.
--
-- O QUE ISTO E
-- A proposta de schema que a Diretoria aprova junto do escopo. Antes de ir para
-- producao ela e quebrada em migrations incrementais, uma por fase, na ordem da
-- secao 13 do escopo. Migracao so acrescenta: nada aqui remove ou altera de forma
-- destrutiva o que a Redacao ja tem, e as tres mudancas subtrativas previstas
-- (policy larga de messages, delete em profiles, profiles_select_shared) viajam em
-- migracao propria marcada com o prefixo limpeza, depois do deploy que deixa de
-- depender delas.
--
-- COMO FOI CONFERIDO
-- Aplicado de fato num Postgres 16 com um ambiente que imita o Supabase (papeis
-- anon, authenticated e service_role; schema auth com users e auth.uid(); pgcrypto,
-- pg_trgm, unaccent e citext; substitutos para pg_cron e pg_net) e com as 21
-- migrations da Redacao carregadas antes. Resultado: aplica do zero sem nenhum erro.
-- Estado depois de aplicar: 68 tabelas, mais de 200 policies, 32 funcoes auxiliares
-- em private, dezenas de triggers e indices, com RLS ligada em todas as tabelas.
-- A suite pgTAP do anexo 02b roda sobre este arquivo: 508 testes, todos verdes.
-- Escrever aquela suite revelou onze defeitos que a leitura do codigo nao tinha
-- pego, entre eles quatro que impediam o sistema de funcionar: documento sigiloso
-- que ninguem conseguia liberar, aviso que nenhuma sessao conseguia alterar,
-- trilha que recusava gravacao de usuario comum e pedido de autorizacao que nao
-- nascia. Todos corrigidos aqui, cada um com comment on citando o numero do teste.
-- Teste de fumaca da trilha: eventos gravados encadeiam, verificar_cadeia devolve
-- integra, adulteracao feita por dentro do banco derruba a verificacao, e update e
-- delete sao recusados pelo trigger para qualquer role.
-- Duas ressalvas honestas: o cluster de conferencia e Postgres 16, nao 17, e o
-- arquivo nao e idempotente, porque create policy nao aceita if not exists; rodar
-- duas vezes no mesmo banco acusa policy repetida, o que nao acontece em migracao,
-- que roda uma vez so.

-- ============================================================
-- 00. Base: extensões, schemas, enums, funções auxiliares de RLS, identidade, setores, papéis e permissões
-- ============================================================

-- ============================================================
-- 20260902090000_cvrj_intranet_base.sql
-- Intranet CVB-RJ, parte 1 de 4: base comum.
--
-- O que entra aqui: extensoes, schemas, os tres enums reais do Postgres,
-- as funcoes auxiliares de RLS no schema private, a identidade (perfil
-- estendido, setores, vinculos, convites, formacoes, credenciais, termos,
-- consentimentos), os papeis e permissoes, o hook de token, a governanca
-- (decisoes da Diretoria e politica de assinatura), o schema operacao e o
-- RLS mais os GRANTs de tudo isso.
--
-- O que NAO entra: grupos, mural, biblioteca, autorizacao, trilha e lgpd.
-- Essas partes vem em migracoes proprias, depois desta.
--
-- Origem dos padroes transpostos (nenhuma linha de codigo de projeto GPL ou
-- AGPL foi copiada; apenas nomes de campos, estados e regras):
--   - exemplo oficial da Supabase (Apache-2.0), examples/slack-clone:
--     user_roles, role_permissions, app_permission, authorize() e o custom
--     access token hook. Aqui viram usuario_papeis, papel_permissoes,
--     public.permissao, public.autorizar() e custom_access_token_hook().
--   - Redacao CVB-RJ: funcoes security definer no schema private com
--     search_path vazio (20260820183812_cvrj_editorial_rls.sql), trigger de
--     atualizado_em no molde de touch_social_publications, e o registro de
--     consentimento como prova de newsletter_inscritos.
--   - Jorvik (Croce Rossa Italiana): Appartenenza (membro, inizio, fine,
--     terminazione, precedente, confermata) vira vinculos; Delega (oggetto,
--     inizio, fine, firmatario) vira usuario_papeis e delegacoes; Sede em
--     arvore vira setores; Documento (tipo, expires) vira credenciais.
--   - HumHub: Space (visibility, join_policy, status) informa setores.ativo e
--     o desenho de grupos, que fica na parte de contato e mural.
--   - Open Social: campos de perfil (self_introduction, expertise, interests,
--     show_email) viram apresentacao, competencias, interesses, email_visivel.
--   - Razikus (Apache-2.0), 20250107210416_MFA.sql: is_user_authenticated()
--     lendo a claim aal vira private.exige_aal2(), sem escrever no schema auth.
--   - Makerkit Lite (MIT): username por split_part e o hardening inicial que
--     revoga privilegios de public e anon.
--   - SEI: nivel de acesso com hipotese legal e dado pessoal restrito por
--     padrao, que aqui aparece na separacao profiles / profiles_restritos.
--   - IFRC Volunteer Management Cycle: estados do vinculo.
--   - IFRC VDMS sobre CiviCRM: civicrm_contact_id reservado.
--   - Papermark, XWiki, Plone, Mayan, Nextcloud Approval, Documenso e
--     DRK Rundlaufbeschlusse informam as partes 2, 3 e 4, nao esta.
--
-- Regra da casa: migracao so acrescenta. Nada da Redacao e removido aqui.
-- Estado de ciclo de vida em ingles; vocabulario institucional em portugues.
-- ============================================================


-- ============================================================
-- 1. Extensoes
-- ============================================================

-- Schema padrao de extensoes do Supabase. Criado por seguranca para que a
-- migracao rode tambem num Postgres limpo de desenvolvimento.
create schema if not exists extensions;

-- pgcrypto fica declarada apenas por gen_random_bytes(), que e o que alimenta
-- o codigo de verificacao. Ela nao encadeia auditoria.eventos e nao calcula o
-- SHA-256 do token de convite: o hash de toda a base usa o sha256() nativo do
-- pg_catalog do Postgres 17, uma unica API aqui e na parte de autorizacao e
-- auditoria. gen_random_uuid() ja e nativo no Postgres 13+, entao a extensao
-- nao existe por causa da chave primaria.
create extension if not exists pgcrypto with schema extensions;

-- citext foi avaliada e NAO e usada: e-mail e guardado em text ja normalizado
-- pela aplicacao, com indice unico sobre lower(email), que e o padrao que a
-- Redacao adotou em newsletter_inscritos. Um tipo a menos para migrar depois.
-- unaccent tambem fica de fora: nao e immutable e por isso nao pode entrar em
-- coluna gerada; a remocao de acento na busca acontece na borda, na consulta.
-- pg_cron nao e criada aqui: e decisao de painel do projeto, conferida na
-- fase 0, e os jobs pertencem a parte de operacao.


-- ============================================================
-- 2. Schemas
--
-- public   o que a sessao da pessoa le e escreve, sempre sob RLS.
-- private  so funcoes security definer com search_path vazio, nunca tabelas.
-- auditoria  trilha append-only, catalogo de fluxos, verificador e ancoras.
--            Criado aqui vazio; as tabelas vem na parte 4.
-- operacao   medicao, fila de e-mail e limite de taxa.
-- ============================================================

create schema if not exists private;
create schema if not exists auditoria;
create schema if not exists operacao;

comment on schema private is
  'So funcoes security definer com search_path vazio, chamadas pelas policies. Nunca guarda tabela. Padrao da Redacao, migration 20260820183812_cvrj_editorial_rls.sql.';
comment on schema auditoria is
  'Trilha append-only, catalogo de fluxos neutros, verificador e ancoras. Leitura so por administrador e auditor; escrita por funcao security definer ou job. Tabelas na parte 4.';
comment on schema operacao is
  'Medicao de uso, fila de e-mail com orcamento diario e limite de taxa das rotas publicas. Leitura so por administrador e auditor; escrita por job.';

revoke all on schema private   from public, anon;
revoke all on schema auditoria from public, anon;
revoke all on schema operacao  from public, anon;


-- ============================================================
-- 3. Enums reais do Postgres
--
-- So tres, e por um motivo declarado: atravessam muitas tabelas ou entram na
-- assinatura de funcao. Todo o resto do vocabulario controlado e text com
-- check na propria tabela, porque enum so cresce por alter type em migracao
-- propria e isso trava a evolucao de vocabulario que muda com a norma.
--
-- Os catalogos que NAO viraram enum, e onde cada um mora:
--   papel_institucional  -> tabela public.papeis (esta migracao)
--   hipotese_legal       -> tabela public.hipoteses_legais (parte biblioteca)
--   nivel_acesso, papel_local_pasta, origem_versao, backend_armazenamento,
--   estado_extracao, resultado_validador_iti, orgao_produtor, estado_modelo
--                        -> check nas tabelas da parte biblioteca
--   papel_no_grupo, tipo_grupo, visibilidade_grupo, entrada_grupo,
--   estado_grupo, estado_membro_grupo, origem_membro_grupo, estado_aviso,
--   prioridade_aviso, tipo_publico_aviso, origem_abertura, estado_comentario
--                        -> check nas tabelas da parte contato e mural
--   estado_autorizacao_leve, estado_autorizacao_documento, estado_etapa,
--   decisao_etapa, acao_ao_expirar, tipo_gestao, estado_assinatura,
--   metodo_assinatura, acao_trilha, origem_verificacao
--                        -> check nas tabelas da parte autorizacao e auditoria
--   tipo_pedido_titular, estado_pedido_titular, risco_incidente,
--   estado_incidente     -> check nas tabelas da parte lgpd
--   tipo_conta, tipo_vinculo, estado_vinculo, motivo_termino, tipo_setor,
--   visibilidade_diretorio, ultimo_acesso_provedor, finalidade_consentimento,
--   tipo_formacao, tipo_credencial, estado_credencial, estado_termo,
--   estado_decisao_institucional, tipo_notificacao, prioridade_email,
--   estado_fila_email, metrica_uso_plano
--                        -> check nas tabelas desta migracao
-- ============================================================

do $$
begin
  if not exists (select 1 from pg_type where typname = 'permissao' and typnamespace = 'public'::regnamespace) then
    create type public.permissao as enum (
      'pessoa.convidar',
      'pessoa.confirmar_vinculo',
      'pessoa.ver_restrito',
      'pessoa.editar_restrito',
      'papel.conceder',
      'papel.revogar',
      'delegacao.criar',
      'grupo.criar',
      'grupo.administrar',
      'mural.publicar',
      'mural.aprovar',
      'mural.moderar',
      'mural.ver_relatorio',
      'documento.enviar',
      'documento.versionar',
      'documento.mover',
      'documento.classificar',
      'documento.permissionar',
      'documento.eliminar',
      'autorizacao.abrir',
      'autorizacao.aprovar',
      'autorizacao.homologar',
      'autorizacao.assinar',
      'autorizacao.regrar',
      'assinatura.conferir',
      'trilha.ler_completa',
      'lgpd.responder_titular',
      'operacao.administrar'
    );
  end if;

  if not exists (select 1 from pg_type where typname = 'tipo_ato' and typnamespace = 'public'::regnamespace) then
    create type public.tipo_ato as enum (
      'uso_imagem',
      'participacao_acao',
      'ressarcimento',
      'autorizacao_despesa',
      'acesso_pasta',
      'reativacao_vinculo',
      'termo_adesao',
      'termo_desligamento',
      'consentimento_lgpd',
      'autorizacao_imagem',
      'ata_junta',
      'ata_assembleia',
      'ata_diretoria',
      'oficio',
      'parecer',
      'prestacao_contas',
      'politica',
      'procedimento',
      'relatorio',
      'certificado'
    );
  end if;

  if not exists (select 1 from pg_type where typname = 'nivel_assinatura' and typnamespace = 'public'::regnamespace) then
    create type public.nivel_assinatura as enum (
      'nenhuma',
      'simples',
      'avancada',
      'qualificada'
    );
  end if;
end $$;

comment on type public.permissao is
  'Permissoes nomeadas no formato entidade.acao. Copia do app_permission do exemplo oficial slack-clone da Supabase (Apache-2.0), com os valores da casa. E o parametro de public.autorizar(): as policies chamam permissao, nunca papel. assinatura.conferir e da Secretaria, que confere o resultado do validador do ITI (decisao D34): separada de autorizacao.homologar, concedida so a diretoria, que costuma ser quem assina. Em base onde o tipo ja existe, esse valor entra por migracao propria e isolada, porque alter type de enum nao convive com o uso do valor novo na mesma transacao.';
comment on type public.tipo_ato is
  'Vocabulario unico do que a instituicao pratica. Os seis primeiros valores sao tramites leves sem arquivo; do setimo em diante o ato nasce como minuta na biblioteca. autorizacao_despesa e o ato previo, sem arquivo: a Lei 9.608 so admite ressarcir despesa expressamente autorizada, e por isso ressarcimento, que e o pedido posterior ao gasto, passa a exigir uma autorizacao previa aprovada e vigente. Em base onde o tipo ja existe, esse valor entra por migracao propria e isolada, antes das partes que o consomem, porque alter type de enum nao convive com o uso do valor novo na mesma transacao. Usado por politicas_assinatura, autorizacao_regras, autorizacoes, tipos_documentais e, por heranca, modelos_documento.';
comment on type public.nivel_assinatura is
  'Escala do art. 4 da Lei 14.063/2020, em portugues porque traduzir perderia a referencia normativa. Gravado por documento, como manda a leitura da recomendacao (docs/03, secao 9).';


-- ============================================================
-- 4. Funcoes utilitarias
-- ============================================================

-- Molde de touch_social_publications e touch_newsletter_inscritos da Redacao.
-- search_path vazio porque funcao com search_path mutavel e vetor de sequestro
-- de nome de objeto, e o advisor do Supabase sinaliza por isso.
create or replace function public.tocar_atualizado_em()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.atualizado_em = now();
  return new;
end;
$$;

comment on function public.tocar_atualizado_em() is
  'Mantem atualizado_em em toda tabela que sofre update. Molde de public.touch_social_publications da Redacao (20260825120000).';

-- array_to_string e marcada stable em algumas versoes do Postgres, e coluna
-- gerada exige expressao immutable. Este embrulho declara o que de fato vale
-- para text[]: a saida so depende da entrada.
create or replace function public.lista_para_texto(p_lista text[])
returns text
language sql
immutable
parallel safe
set search_path = ''
as $$
  select coalesce(array_to_string(p_lista, ' '), '');
$$;

comment on function public.lista_para_texto(text[]) is
  'Junta um text[] em texto unico para entrar em coluna gerada de busca. Existe porque array_to_string nao e declarada immutable e coluna gerada recusa expressao nao immutable.';

-- Escopo do papel: coordenador e instrutor sao por setor, os demais globais.
-- A regra mora no catalogo public.papeis e nao em check, porque um papel novo
-- precisa entrar sem alter type e sem alterar constraint.
create or replace function public.validar_escopo_do_papel()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_escopo text;
  v_ativo  boolean;
begin
  select p.escopo, p.ativo into v_escopo, v_ativo
    from public.papeis p where p.slug = new.papel;

  if v_escopo is null then
    raise exception 'Papel % nao existe no catalogo public.papeis.', new.papel using errcode = '23503';
  end if;

  if tg_op = 'INSERT' and not v_ativo then
    raise exception 'Papel % esta desativado e nao pode ser concedido.', new.papel using errcode = '23514';
  end if;

  if v_escopo = 'setor' and new.setor_id is null then
    raise exception 'O papel % e por setor: setor_id e obrigatorio.', new.papel using errcode = '23514';
  end if;

  if v_escopo = 'global' and new.setor_id is not null then
    raise exception 'O papel % e global: setor_id precisa ser nulo.', new.papel using errcode = '23514';
  end if;

  return new;
end;
$$;

comment on function public.validar_escopo_do_papel() is
  'Confere escopo (global ou setor) e atividade do papel ao conceder papel ou delegacao. Substitui o check que um enum de papeis exigiria.';

-- LGPD art. 11: dado de saude nao admite legitimo interesse. Sem consentimento
-- vigente de finalidade saude, o banco recusa a gravacao, e nao so a tela.
create or replace function public.exigir_consentimento_saude()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (new.tipo_sanguineo is not null or new.restricoes_saude is not null)
     and not exists (
       select 1 from public.consentimentos c
       where c.profile_id = new.profile_id
         and c.finalidade = 'saude'
         and c.revogado_em is null
     )
  then
    raise exception 'Dado de saude (LGPD art. 11) exige consentimento vigente de finalidade saude para o titular %.', new.profile_id
      using errcode = '23514';
  end if;
  return new;
end;
$$;

comment on function public.exigir_consentimento_saude() is
  'Recusa gravar tipo sanguineo e restricoes de saude sem consentimento vigente (LGPD art. 11, consentimento especifico e destacado).';

-- Consentimento e prova (LGPD art. 8, paragrafo 6). A linha nunca e apagada e
-- nunca e reescrita: revogar preenche revogado_em, e conceder de novo e linha
-- nova. Padrao copiado de newsletter_inscritos da Redacao (20260831160000).
create or replace function public.congelar_consentimento()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.profile_id     is distinct from old.profile_id
     or new.finalidade     is distinct from old.finalidade
     or new.versao_politica is distinct from old.versao_politica
     or new.concedido_em   is distinct from old.concedido_em
     or new.evidencia      is distinct from old.evidencia
     or new.origem         is distinct from old.origem
     or new.registrado_por is distinct from old.registrado_por
     or new.comprovante_documento_id is distinct from old.comprovante_documento_id
  then
    raise exception 'Consentimento e prova: so revogado_em pode mudar. Nova concessao e linha nova.'
      using errcode = '23514';
  end if;

  if old.revogado_em is not null and new.revogado_em is distinct from old.revogado_em then
    raise exception 'Consentimento ja revogado em %; revogacao nao se desfaz.', old.revogado_em
      using errcode = '23514';
  end if;

  return new;
end;
$$;

comment on function public.congelar_consentimento() is
  'Deixa alterar apenas revogado_em em public.consentimentos. Sem isto, a prova que a LGPD manda guardar poderia ser reescrita.';

create or replace function public.normalizar_email_convite()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.email = lower(btrim(new.email));
  return new;
end;
$$;

comment on function public.normalizar_email_convite() is
  'Normaliza o e-mail do convite no banco. Defesa em profundidade: o indice unico usa lower(), mas um caminho de escrita futuro pode esquecer de normalizar.';

-- Teto de administradores e exclusividade entre papel somente leitura e papel
-- de escrita. As duas regras ja estavam no texto e agora valem no banco,
-- porque concessao de papel entra por mais de uma tela.
create or replace function public.validar_exclusividade_do_papel()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_somente_leitura boolean;
  v_exclusivo       boolean;
  v_vigentes        integer;
  v_conflito        text;
begin
  select p.somente_leitura into v_somente_leitura
    from public.papeis p where p.slug = new.papel;

  -- Papel fora do catalogo ja e recusado por public.validar_escopo_do_papel().
  if v_somente_leitura is null then
    return new;
  end if;

  -- A secao 5.3 do escopo nomeia auditor e parceiro_externo como os dois papeis
  -- mutuamente exclusivos com papel de escrita, e na mesma frase diz que
  -- papeis.somente_leitura e verdadeiro para auditor. Ou seja: a marca da coluna
  -- e lida, mas nao esgota a regra. Por isso a exclusividade e decidida aqui,
  -- por marca da coluna ou por nome do papel, e o seed nao e mexido: marcar
  -- parceiro_externo como somente_leitura contrariaria o texto do escopo, o
  -- teste que confere a coluna papel a papel e o proprio seed, que da a
  -- parceiro_externo a permissao de escrita autorizacao.assinar. Parceiro
  -- externo nao e papel que so le; e papel que nao acumula.
  v_exclusivo := coalesce(v_somente_leitura, false)
                 or new.papel in ('auditor','parceiro_externo');

  -- Concessao que ja nasce encerrada nao disputa teto nem exclusividade.
  if new.fim is not null and new.fim <= now() then
    return new;
  end if;

  if new.papel = 'administrador' then
    select count(*) into v_vigentes
      from public.usuario_papeis up
     where up.papel = 'administrador'
       and (up.fim is null or up.fim > now())
       and up.id <> new.id;

    if v_vigentes >= 2 then
      raise exception 'Teto de administradores: ja existem duas concessoes vigentes do papel administrador e esta seria a terceira.'
        using errcode = '23514';
    end if;
  end if;

  select up.papel into v_conflito
    from public.usuario_papeis up
    join public.papeis p on p.slug = up.papel
   where up.user_id = new.user_id
     and up.id <> new.id
     and (up.fim is null or up.fim > now())
     and (coalesce(p.somente_leitura, false)
          or up.papel in ('auditor','parceiro_externo')) is distinct from v_exclusivo
   limit 1;

  if v_conflito is not null and v_exclusivo then
    raise exception 'Exclusividade de papel: % nao acumula com papel de escrita e a pessoa ja tem o papel %, vigente.', new.papel, v_conflito
      using errcode = '23514';
  elsif v_conflito is not null then
    raise exception 'Exclusividade de papel: % escreve e nao convive com o papel %, que nao acumula e ja e vigente para esta pessoa.', new.papel, v_conflito
      using errcode = '23514';
  end if;

  return new;
end;
$$;

comment on function public.validar_exclusividade_do_papel() is
  'Aplica no banco duas regras que ate agora so estavam no texto: no maximo duas concessoes vigentes do papel administrador, e exclusividade mutua entre papel que nao acumula e qualquer papel de escrita. Papel que nao acumula e o que tem public.papeis.somente_leitura verdadeiro ou cujo slug e auditor ou parceiro_externo. A versao anterior decidia so pela coluna somente_leitura, verdadeira apenas para auditor no seed, e por isso deixava parceiro_externo receber papel de escrita, contra a secao 5.3, que nomeia os dois. A correcao ficou aqui, na funcao, e nao no seed: a mesma secao 5.3 diz que somente_leitura e verdadeiro para auditor, um teste confere a coluna papel a papel, e parceiro_externo recebe no seed a permissao de escrita autorizacao.assinar, de modo que marcar a coluna nele seria dizer no banco algo que o escopo nao diz e que a matriz de permissoes desmente. Nao substitui public.validar_escopo_do_papel(), que continua conferindo escopo e atividade do papel. Defeito encontrado pela suite pgTAP do anexo 02b.';

-- Membro Juvenil (16 a 18 anos) esta decidido como nao nesta rodada, entao o
-- banco recusa a data de nascimento de quem ainda nao tem 18 anos.
create or replace function public.exigir_maioridade()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.data_nascimento is not null
     and new.data_nascimento > (current_date - interval '18 years')
  then
    raise exception 'Cadastro restrito exige 18 anos completos na data da gravacao para o titular %. Procure a Secretaria.', new.profile_id
      using errcode = '23514';
  end if;
  return new;
end;
$$;

comment on function public.exigir_maioridade() is
  'Recusa linha de public.profiles_restritos cuja data_nascimento implique idade inferior a 18 anos na data da gravacao. A regra vale enquanto a decisao sobre Membros Juvenis de 16 a 18 anos estiver decidida como nao nesta rodada. E a evidencia tecnica que sustenta o enquadramento de pequeno porte assumido: a Resolucao CD/ANPD 2/2022 trata dado de crianca e de adolescente como criterio especifico de alto risco, e o banco que recusa a data nao trata o dado.';

-- Conta de servico e integracao, nao pessoa: nao ganha dado pessoal restrito.
-- E trigger e nao check porque check nao consulta outra tabela.
create or replace function public.recusar_restrito_de_conta_servico()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if exists (
    select 1 from public.profiles p
    where p.id = new.profile_id and p.tipo_conta = 'servico'
  ) then
    raise exception 'Conta de servico nao tem dado pessoal: public.profiles_restritos nao recebe linha do perfil %.', new.profile_id
      using errcode = '23514';
  end if;
  return new;
end;
$$;

comment on function public.recusar_restrito_de_conta_servico() is
  'Impede que perfil com tipo_conta servico receba linha em public.profiles_restritos. E o check que a coluna nao pode ter, porque check nao consulta outra tabela.';

create or replace function public.espelhar_desativacao()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  new.active = (new.desativado_em is null);
  return new;
end;
$$;

comment on function public.espelhar_desativacao() is
  'Mantem public.profiles.active como espelho de desativado_em: verdadeiro quando desativado_em e nulo, falso quando esta preenchido. Sem isto ha dois campos concorrentes para o mesmo fato, porque a Redacao le active e o diretorio da intranet filtra por desativado_em, e alguem desligado num app continua ativo no outro. active e mantida por espelho enquanto a Redacao depender dela e sai em migracao posterior marcada -- limpeza:.';


-- ============================================================
-- 5. Catalogo institucional: setores
-- ============================================================

create table if not exists public.setores (
  id                  uuid primary key default gen_random_uuid(),
  workspace_id        uuid not null references public.workspaces (id) on delete cascade,
  slug                text not null check (slug ~ '^[a-z0-9-]{2,40}$'),
  nome                text not null,
  tipo                text not null check (tipo in ('coordenacao','orgao','externo')),
  parent_id           uuid references public.setores (id) on delete restrict,
  email_institucional text,
  restrito_por_padrao boolean not null default false,
  ativo               boolean not null default true,
  criado_em           timestamptz not null default now(),
  atualizado_em       timestamptz not null default now(),
  constraint setores_parent_diferente check (parent_id is null or parent_id <> id)
);

create unique index if not exists setores_workspace_slug_idx on public.setores (workspace_id, slug);
create index if not exists setores_parent_id_idx  on public.setores (parent_id);
create index if not exists setores_ativos_idx     on public.setores (workspace_id) where ativo;

drop trigger if exists setores_tocar on public.setores;
create trigger setores_tocar before update on public.setores
  for each row execute function public.tocar_atualizado_em();

comment on table public.setores is
  'Organograma: as coordenacoes e orgaos da filial, em arvore. Dono de murais, de pastas e de papeis por setor. Transposto da Sede em arvore do Jorvik (anagrafica, ModelloAlbero). Nao guarda visibilidade nem politica de entrada: essas passaram a viver so em public.grupos, na parte de contato e mural, para nao existirem duas fontes da mesma regra.';
comment on column public.setores.slug is
  'Chave de rota e chave de ponte: e o valor que workspace_members.coordination da Redacao carrega hoje e que o hook de token resolve para setor_id.';
comment on column public.setores.tipo is
  'coordenacao, orgao ou externo. As sete coordenacoes reconhecidas pelo mapa do ecossistema entram como coordenacao.';
comment on column public.setores.restrito_por_padrao is
  'true no setor Saude: documento que nasce ali assume nivel restrito, porque dado de saude e art. 11 da LGPD. Medida tecnica, nao enquadramento (o enquadramento e a decisao D05).';
comment on column public.setores.ativo is
  'Setor nao e apagado: e arquivado com ativo = false e continua legivel. Padrao STATUS_ARCHIVED do Space do HumHub.';
comment on column public.setores.parent_id is
  'Setor mae. Restrict de proposito: mover a arvore e ato consciente, nunca efeito colateral de um delete.';


-- ============================================================
-- 6. Papeis e permissoes
--
-- Padrao do exemplo oficial slack-clone da Supabase, com uma troca: app_role
-- virou a tabela public.papeis, para que um papel novo entre sem alter type.
-- app_permission continua enum real (public.permissao) porque e parametro de
-- funcao. As duas unicas tabelas de public sem workspace_id sao estas: sao
-- catalogo da instalacao, nao conteudo do espaco.
-- ============================================================

create table if not exists public.papeis (
  slug            text primary key check (slug ~ '^[a-z_]{3,40}$'),
  nome            text not null,
  descricao       text,
  escopo          text not null check (escopo in ('global','setor')),
  exige_mfa       boolean not null default false,
  somente_leitura boolean not null default false,
  alcance         smallint not null check (alcance between 0 and 1000),
  ativo           boolean not null default true,
  criado_em       timestamptz not null default now(),
  atualizado_em   timestamptz not null default now()
);

create index if not exists papeis_alcance_idx on public.papeis (alcance desc) where ativo;

drop trigger if exists papeis_tocar on public.papeis;
create trigger papeis_tocar before update on public.papeis
  for each row execute function public.tocar_atualizado_em();

comment on table public.papeis is
  'Catalogo dos dez papeis institucionais. E tabela e nao enum, ao contrario do app_role do exemplo oficial da Supabase, para que um papel novo entre sem alter type. Uma das duas tabelas de public sem workspace_id: catalogo da instalacao.';
comment on column public.papeis.slug is
  'Chave natural e chave estrangeira de usuario_papeis, papel_permissoes, delegacoes, convites.papel_inicial e das colunas de papel das partes 2 a 4. Excecao consciente a regra de uuid como chave primaria em public: catalogo de valores, nao registro do espaco.';
comment on column public.papeis.escopo is
  'global vale em toda a filial; setor vale so no setor da atribuicao. coordenador e instrutor sao por setor; os demais, globais.';
comment on column public.papeis.exige_mfa is
  'true para administrador, diretoria, secretaria, auditor e encarregado. Quem recebe um desses e nao tem fator TOTP verificado le, mas nao decide: private.exige_aal2() barra a escrita de decisao. Coordenador, comunicacao e instrutor ficam em false: a obrigatoriedade para esses tres e decisao pendente da Diretoria, com prazo e comunicacao previos, e ate la o segundo fator e recomendado e cobrado na tela, nao exigido pelo banco. O motivo e operacional: coordenador costuma ser voluntario com aparelho proprio, e a exigencia trava a etapa 1 de todo tramite quando a pessoa troca de celular.';
comment on column public.papeis.somente_leitura is
  'true so para auditor, como diz a secao 5.3. O papel le a trilha completa e nunca escreve. A coluna nao esgota a exclusividade de papel: parceiro_externo tambem nao acumula com papel de escrita e nao esta marcado aqui, porque assina autorizacao. Quem decide a exclusividade e public.validar_exclusividade_do_papel(), que le esta coluna e mais o nome do papel. Defeito encontrado pela suite pgTAP do anexo 02b.';
comment on column public.papeis.alcance is
  'Ordem usada pelo hook de token para escolher a claim user_role quando a pessoa tem varios papeis. Maior alcance vence.';

create table if not exists public.papel_permissoes (
  id        uuid primary key default gen_random_uuid(),
  papel     text not null references public.papeis (slug) on delete cascade,
  permissao public.permissao not null,
  criado_em timestamptz not null default now(),
  unique (papel, permissao)
);

create index if not exists papel_permissoes_papel_idx on public.papel_permissoes (papel);

comment on table public.papel_permissoes is
  'Mapa de papel para permissao, lido por public.autorizar(). Copia do role_permissions do exemplo oficial slack-clone da Supabase. Segunda e ultima tabela de public sem workspace_id.';
comment on column public.papel_permissoes.permissao is
  'A policy chama a permissao nomeada, nunca o papel. Trocar quem pode o que e um insert aqui, nao uma migracao de policy.';


-- ============================================================
-- 7. Perfil estendido (tabela da Redacao; migracao so acrescenta)
-- ============================================================

alter table public.profiles
  add column if not exists nome_social            text,
  add column if not exists tipo_conta             text not null default 'equipe',
  add column if not exists email_contato          text,
  add column if not exists email_visivel          boolean not null default false,
  add column if not exists telefone               text,
  add column if not exists telefone_visivel       boolean not null default false,
  add column if not exists apresentacao           text,
  add column if not exists competencias           text[] not null default '{}',
  add column if not exists interesses             text[] not null default '{}',
  add column if not exists setor_principal_id     uuid references public.setores (id) on delete set null,
  add column if not exists visibilidade_diretorio text not null default 'setor',
  add column if not exists acesso_expira_em       timestamptz,
  add column if not exists civicrm_contact_id     text,
  add column if not exists registro_nacional_id   text,
  add column if not exists ultimo_acesso_em       timestamptz,
  add column if not exists ultimo_acesso_provedor text,
  add column if not exists mfa_verificado_em      timestamptz,
  add column if not exists receber_resumo         boolean not null default true,
  add column if not exists receber_imediatos      boolean not null default true,
  add column if not exists onboarding_concluido_em timestamptz,
  add column if not exists desativado_em          timestamptz,
  add column if not exists eliminado_em           timestamptz;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_tipo_conta_check') then
    alter table public.profiles add constraint profiles_tipo_conta_check
      check (tipo_conta in ('equipe','voluntario','externo','servico'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'profiles_visibilidade_diretorio_check') then
    alter table public.profiles add constraint profiles_visibilidade_diretorio_check
      check (visibilidade_diretorio in ('todos','setor','oculto'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'profiles_ultimo_acesso_provedor_check') then
    alter table public.profiles add constraint profiles_ultimo_acesso_provedor_check
      check (ultimo_acesso_provedor is null or ultimo_acesso_provedor in ('google','email','senha'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'profiles_acesso_expira_check') then
    alter table public.profiles add constraint profiles_acesso_expira_check
      check (acesso_expira_em is null or tipo_conta = 'externo');
  end if;
end $$;

-- Coluna gerada depois das colunas de origem, e sem telefone nem e-mail: o
-- diretorio busca por quem a pessoa e, nunca por como falar com ela
-- (LGPD art. 6, III, minimizacao).
alter table public.profiles
  add column if not exists busca tsvector
  generated always as (
    to_tsvector('portuguese',
      coalesce(full_name, '') || ' ' ||
      coalesce(nome_social, '') || ' ' ||
      coalesce(job_title, '') || ' ' ||
      coalesce(apresentacao, '') || ' ' ||
      public.lista_para_texto(competencias) || ' ' ||
      public.lista_para_texto(interesses)
    )
  ) stored;

create index if not exists profiles_busca_idx        on public.profiles using gin (busca);
create index if not exists profiles_competencias_idx on public.profiles using gin (competencias);
create index if not exists profiles_setor_principal_idx on public.profiles (setor_principal_id);
create index if not exists profiles_ativos_idx       on public.profiles (id) where desativado_em is null and eliminado_em is null;

drop trigger if exists profiles_espelhar_desativacao on public.profiles;
create trigger profiles_espelhar_desativacao
  before insert or update of desativado_em on public.profiles
  for each row execute function public.espelhar_desativacao();

comment on column public.profiles.nome_social is
  'dado_pessoal | nome social, exibido antes do nome civil quando preenchido. Campo do formulario nacional CVB-CADVOL-FORM01.';
comment on column public.profiles.tipo_conta is
  'Governa a porta de entrada e a validade: equipe entra por Google no dominio, voluntario por codigo de seis digitos, externo por convite com acesso_expira_em preenchido. Substitui o account_kind em ingles proposto na decisao D03. Default equipe porque as linhas herdadas da Redacao sao a equipe editorial. servico e a conta de integracao, usada hoje apenas pelo Cerebro: nasce sem linha em public.profiles_restritos, nunca aparece no diretorio, tem credencial rotacionada anualmente e e registrada em public.decisoes_institucionais.';
comment on column public.profiles.email_contato is
  'dado_pessoal | e-mail exibido no diretorio, que pode diferir do e-mail de login. So aparece quando email_visivel e verdadeiro. Do field_profile_show_email do Open Social.';
comment on column public.profiles.telefone is
  'dado_pessoal | telefone. No diretorio sai apenas para a propria pessoa e para quem tem pessoa.ver_restrito, e ainda assim so quando telefone_visivel for verdadeiro e existir consentimento vigente em public.consentimentos com finalidade telefone_no_diretorio e revogado_em nulo. Essa e a unica regra.';
comment on column public.profiles.apresentacao is
  'dado_pessoal | texto livre curto. Do field_profile_self_introduction do Open Social.';
comment on column public.profiles.competencias is
  'Do field_profile_expertise do Open Social. Entra na busca e tem indice GIN proprio para filtro por competencia.';
comment on column public.profiles.interesses is
  'Do field_profile_interests do Open Social.';
comment on column public.profiles.setor_principal_id is
  'Afiliacao primaria, do field_group_affiliation do Open Social. E a claim setor_principal do hook de token.';
comment on column public.profiles.visibilidade_diretorio is
  'Escolha da pessoa sobre quem a ve. Prevalece sobre o papel de quem olha, exceto para secretaria e administrador (permissao pessoa.ver_restrito).';
comment on column public.profiles.acesso_expira_em is
  'So faz sentido em conta externa: convidado com prazo. Check garante isso.';
comment on column public.profiles.civicrm_contact_id is
  'Reservado para sincronizar com o VDMS da IFRC sobre CiviCRM, se a CVB nacional aderir. Nada e enviado hoje: envio ao nacional e transferencia entre controladores e depende de base legal (decisao pendente D06).';
comment on column public.profiles.registro_nacional_id is
  'Reservado para o numero no Registro Unico Nacional de Voluntarios. O Estatuto (art. 67, paragrafo 2) apoia cadastro proprio da filial.';
comment on column public.profiles.ultimo_acesso_provedor is
  'google, email ou senha. E o que autoriza o passo 7 do roteiro de migracao: a senha sintetica so e desativada quando ninguem mais aparecer como senha.';
comment on column public.profiles.mfa_verificado_em is
  'Espelho de leitura da ultima verificacao TOTP, gravado so por public.registrar_verificacao_mfa(). A idade da verificacao usada pelas RPCs de decisao e de assinatura e lida da claim amr do JWT, nunca desta coluna.';
comment on column public.profiles.desativado_em is
  'Desligamento. Nada e apagado: a saida e update de coluna de data.';
comment on column public.profiles.eliminado_em is
  'Eliminacao LGPD concluida. A partir daqui os campos pessoais estao nulos e o UUID fica orfao na trilha.';
comment on column public.profiles.busca is
  'tsvector em portuguese sobre nome, nome social, funcao, apresentacao, competencias e interesses. Nao indexa telefone nem e-mail, por minimizacao.';


-- ============================================================
-- 8. Consentimentos
--
-- Vem antes de profiles_restritos porque o trigger de dado de saude le esta
-- tabela. Padrao de prova copiado de newsletter_inscritos da Redacao
-- (20260831160000): texto aceito, momento, evidencia, linha nunca apagada.
-- ============================================================

create table if not exists public.consentimentos (
  id              uuid primary key default gen_random_uuid(),
  workspace_id    uuid not null references public.workspaces (id) on delete cascade,
  profile_id      uuid not null references public.profiles (id) on delete cascade,
  finalidade      text not null check (finalidade in ('imagem','saude','telefone_no_diretorio','whatsapp','politica_de_dados')),
  versao_politica text not null,
  concedido_em    timestamptz not null default now(),
  revogado_em     timestamptz,
  evidencia       jsonb not null default '{}'::jsonb,
  origem          text not null default 'intranet' check (origem in ('intranet','papel','presencial')),
  registrado_por  uuid references public.profiles (id) on delete set null,
  comprovante_documento_id uuid,
  criado_em       timestamptz not null default now(),
  constraint consentimentos_revogacao_posterior check (revogado_em is null or revogado_em >= concedido_em)
);

create index if not exists consentimentos_profile_id_idx on public.consentimentos (profile_id);
create unique index if not exists consentimentos_vigente_idx
  on public.consentimentos (profile_id, finalidade)
  where revogado_em is null;

drop trigger if exists consentimentos_congelar on public.consentimentos;
create trigger consentimentos_congelar before update on public.consentimentos
  for each row execute function public.congelar_consentimento();

comment on table public.consentimentos is
  'Prova de consentimento por finalidade e por versao da politica (LGPD art. 8, paragrafo 4, finalidade especifica; paragrafo 6, prova). Padrao de registro de consentimento copiado de public.newsletter_inscritos da Redacao. Revogacao e linha alterada so em revogado_em, nunca apagamento; nova concessao e linha nova.';
comment on column public.consentimentos.finalidade is
  'Finalidade especifica, em portugues porque e vocabulario da LGPD. Consentimento generico nao vale.';
comment on column public.consentimentos.versao_politica is
  'Versao do texto que a pessoa aceitou. Do data_policy com revisoes do Open Social. Sem isto a instituicao nao consegue provar o que foi aceito.';
comment on column public.consentimentos.evidencia is
  'dado_pessoal | ip, agente, tela e hash do texto exibido. E o unico lugar desta parte com IP em claro, e a tabela e apagavel de proposito: a cadeia de auditoria recebe apenas hash.';
comment on column public.consentimentos.revogado_em is
  'Revogacao. O indice unico parcial garante um consentimento vigente por finalidade e por pessoa.';
comment on column public.consentimentos.origem is
  'intranet quando a propria pessoa aceitou na tela; papel quando veio de ficha assinada; presencial quando foi colhido em acao de campo. Consentimento colhido fora da intranet so vale registrado com o comprovante digitalizado, e sem essa porta a ficha de saude continuaria em papel.';
comment on column public.consentimentos.registrado_por is
  'Quem digitou o consentimento colhido fora da intranet (permissao pessoa.editar_restrito, com private.exige_aal2()). Nulo quando origem e intranet, onde quem consente e quem grava.';
comment on column public.consentimentos.comprovante_documento_id is
  'Aponta para public.documentos, da parte da biblioteca: a ficha assinada digitalizada. Sem chave estrangeira nesta migracao, no mesmo padrao de public.formacoes.comprovante_documento_id.';


-- ============================================================
-- 9. Dados restritos do perfil
--
-- Separados do perfil publico para que o padrao do dado pessoal seja restrito,
-- como no SEI e no SUAP. Coordenador nao le esta tabela.
-- ============================================================

create table if not exists public.profiles_restritos (
  profile_id                  uuid primary key references public.profiles (id) on delete cascade,
  workspace_id                uuid not null references public.workspaces (id) on delete cascade,
  cpf                         text check (cpf is null or cpf ~ '^[0-9]{11}$'),
  rg                          text,
  data_nascimento             date,
  endereco                    jsonb not null default '{}'::jsonb,
  contato_emergencia_nome     text,
  contato_emergencia_telefone text,
  tipo_sanguineo              text check (tipo_sanguineo is null or tipo_sanguineo in ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
  restricoes_saude            text,
  idiomas                     text[] not null default '{}',
  habilitacao                 text,
  criado_em                   timestamptz not null default now(),
  atualizado_em               timestamptz not null default now()
);

create unique index if not exists profiles_restritos_cpf_idx
  on public.profiles_restritos (workspace_id, cpf) where cpf is not null;

drop trigger if exists profiles_restritos_tocar on public.profiles_restritos;
create trigger profiles_restritos_tocar before update on public.profiles_restritos
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists profiles_restritos_consentimento_saude on public.profiles_restritos;
create trigger profiles_restritos_consentimento_saude
  before insert or update on public.profiles_restritos
  for each row execute function public.exigir_consentimento_saude();

drop trigger if exists profiles_restritos_maioridade on public.profiles_restritos;
create trigger profiles_restritos_maioridade
  before insert or update on public.profiles_restritos
  for each row execute function public.exigir_maioridade();

drop trigger if exists profiles_restritos_sem_conta_servico on public.profiles_restritos;
create trigger profiles_restritos_sem_conta_servico
  before insert or update on public.profiles_restritos
  for each row execute function public.recusar_restrito_de_conta_servico();

comment on table public.profiles_restritos is
  'Dados pessoais de nivel restrito e dados sensiveis do formulario nacional CVB-CADVOL-FORM01, separados do perfil publico para que o padrao do dado pessoal seja restrito (SEI e SUAP). Chave primaria e profile_id porque a tabela e extensao 1 para 1 do perfil, nao registro proprio. Coordenador nao le: so a propria pessoa e quem tem pessoa.ver_restrito.';
comment on column public.profiles_restritos.cpf is
  'dado_pessoal | CPF exigido pelo termo de adesao da Lei 9.608 e pela prestacao de contas do MROSC. Base legal art. 7, II.';
comment on column public.profiles_restritos.rg is
  'dado_pessoal | documento de identidade.';
comment on column public.profiles_restritos.data_nascimento is
  'dado_pessoal | idade. Regra de Membro Juvenil (16 a 18 anos, Estatuto) fica fora desta rodada; o convite recusa menor de 18 ate haver termo e fluxo aprovados.';
comment on column public.profiles_restritos.endereco is
  'dado_pessoal | logradouro, numero, complemento, bairro, cidade, UF, CEP.';
comment on column public.profiles_restritos.tipo_sanguineo is
  'dado_sensivel | saude, LGPD art. 11. So grava com consentimento vigente de finalidade saude, conferido por trigger.';
comment on column public.profiles_restritos.restricoes_saude is
  'dado_sensivel | saude, LGPD art. 11. Mesma regra de consentimento do tipo sanguineo. Legitimo interesse nao se aplica.';
comment on column public.profiles_restritos.habilitacao is
  'dado_pessoal | categoria da CNH, quando informada. Existe porque a operacao de GRD precisa saber quem dirige.';


-- ============================================================
-- 10. Vinculos
--
-- Appartenenza do Jorvik (membro, inizio, fine, terminazione, precedente,
-- confermata) somada ao Volunteer Management Cycle da IFRC, que da os estados.
-- ============================================================

create table if not exists public.vinculos (
  id             uuid primary key default gen_random_uuid(),
  workspace_id   uuid not null references public.workspaces (id) on delete cascade,
  profile_id     uuid not null references public.profiles (id) on delete cascade,
  setor_id       uuid references public.setores (id) on delete restrict,
  tipo           text not null check (tipo in ('colaborador','voluntario','instrutor','parceiro_externo','diretoria','servico')),
  estado         text not null default 'new' check (estado in ('new','active','inactive','suspended','terminated')),
  inicio         timestamptz not null default now(),
  fim            timestamptz,
  motivo_termino text check (motivo_termino is null or motivo_termino in ('desligamento','expulsao','suspensao','transferencia','promocao','fim_periodo')),
  anterior_id    uuid references public.vinculos (id) on delete set null,
  confirmado_por uuid references public.profiles (id) on delete set null,
  confirmado_em  timestamptz,
  origem         text not null default 'intranet' check (origem in ('intranet','carga_inicial')),
  observacao     text,
  criado_em      timestamptz not null default now(),
  atualizado_em  timestamptz not null default now(),
  constraint vinculos_fim_posterior     check (fim is null or fim >= inicio),
  constraint vinculos_motivo_com_fim    check (motivo_termino is null or fim is not null),
  constraint vinculos_encerrado_com_fim check (estado <> 'terminated' or fim is not null),
  constraint vinculos_anterior_diferente check (anterior_id is null or anterior_id <> id)
);

create index if not exists vinculos_profile_id_idx on public.vinculos (profile_id);
create index if not exists vinculos_setor_id_idx   on public.vinculos (setor_id);
create index if not exists vinculos_anterior_id_idx on public.vinculos (anterior_id);
create index if not exists vinculos_confirmado_por_idx on public.vinculos (confirmado_por);
create index if not exists vinculos_ativos_idx
  on public.vinculos (workspace_id, setor_id, profile_id) where estado = 'active' and fim is null;

-- Uma pessoa nao tem dois vinculos vigentes do mesmo tipo no mesmo setor.
-- nulls not distinct porque o vinculo institucional geral tem setor_id nulo e
-- tambem precisa ser unico.
create unique index if not exists vinculos_vigente_idx
  on public.vinculos (profile_id, setor_id, tipo) nulls not distinct
  where fim is null;

drop trigger if exists vinculos_tocar on public.vinculos;
create trigger vinculos_tocar before update on public.vinculos
  for each row execute function public.tocar_atualizado_em();

comment on table public.vinculos is
  'Relacao da pessoa com a filial e com um setor ao longo do tempo. Transposto da Appartenenza do Jorvik (anagrafica/models.py) com o mixin ConStorico (inizio, fine); os estados sao as etapas do Volunteer Management Cycle da IFRC. E o que decide quem aparece no diretorio e quem entra no grupo do setor: ninguem aparece antes de estado = active.';
comment on column public.vinculos.tipo is
  'O que a pessoa e para a instituicao num setor e num periodo. Distinto de profiles.tipo_conta, que so governa a porta de entrada.';
comment on column public.vinculos.estado is
  'Ciclo de vida, por isso em ingles (secao 9 do ARQUITETURA.md da Redacao): new, active, inactive, suspended, terminated. Traduzido na borda por lib/status-maps.ts.';
comment on column public.vinculos.motivo_termino is
  'Vocabulario institucional, em portugues. Transposto de Appartenenza.terminazione do Jorvik.';
comment on column public.vinculos.anterior_id is
  'Vinculo que este sucede, em transferencia ou promocao. De Appartenenza.precedente do Jorvik. Historico nao e reescrito: o anterior fica.';
comment on column public.vinculos.confirmado_por is
  'Quem confirmou. De Appartenenza.confermata. O vinculo criado pelo trigger de novo usuario nasce em new e so a Secretaria o leva a active.';
comment on column public.vinculos.origem is
  'intranet no vinculo criado pela adesao normal; carga_inicial no vinculo herdado, gravado em lote por public.confirmar_vinculos_iniciais(). A exigencia de formacao verificada e de termo assinado para chegar a active vale apenas para adesoes posteriores a data de corte registrada em public.decisoes_institucionais: vinculo com origem carga_inicial nao e rebaixado a new por falta delas nesta rodada. Sem essa carga, no dia do lancamento ninguem aparece no diretorio e nenhum mural de setor tem leitor.';
comment on column public.vinculos.observacao is
  'Texto livre operacional. Nunca dado sensivel: dado de saude vive em profiles_restritos, sob consentimento.';


-- ============================================================
-- 11. Atribuicao de papel e delegacao por ausencia
-- ============================================================

create table if not exists public.usuario_papeis (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid not null references public.workspaces (id) on delete cascade,
  user_id       uuid not null references public.profiles (id) on delete cascade,
  papel         text not null references public.papeis (slug) on delete restrict,
  setor_id      uuid references public.setores (id) on delete restrict,
  inicio        timestamptz not null default now(),
  fim           timestamptz,
  concedido_por uuid references public.profiles (id) on delete set null,
  motivo        text,
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  constraint usuario_papeis_fim_posterior check (fim is null or fim >= inicio)
);

create index if not exists usuario_papeis_user_id_idx  on public.usuario_papeis (user_id);
create index if not exists usuario_papeis_papel_idx    on public.usuario_papeis (papel);
create index if not exists usuario_papeis_setor_id_idx on public.usuario_papeis (setor_id);
create index if not exists usuario_papeis_concedido_por_idx on public.usuario_papeis (concedido_por);
create index if not exists usuario_papeis_vigentes_idx
  on public.usuario_papeis (user_id, papel, setor_id) where fim is null;

create unique index if not exists usuario_papeis_vigente_idx
  on public.usuario_papeis (user_id, papel, setor_id) nulls not distinct
  where fim is null;

drop trigger if exists usuario_papeis_tocar on public.usuario_papeis;
create trigger usuario_papeis_tocar before update on public.usuario_papeis
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists usuario_papeis_escopo on public.usuario_papeis;
create trigger usuario_papeis_escopo before insert or update on public.usuario_papeis
  for each row execute function public.validar_escopo_do_papel();

drop trigger if exists usuario_papeis_exclusividade on public.usuario_papeis;
create trigger usuario_papeis_exclusividade before insert or update on public.usuario_papeis
  for each row execute function public.validar_exclusividade_do_papel();
comment on table public.usuario_papeis is
  'Atribuicao de papel a pessoa, com escopo por setor e vigencia, no padrao da Delega do Jorvik (oggetto, inizio, fine, firmatario). Substitui o nome user_roles do exemplo oficial da Supabase, mantendo a funcao: e a fonte das claims do JWT. requireSession() reconfere aqui no banco antes de qualquer acao de aprovacao, nunca so a claim, porque o JWT so muda na renovacao.';
comment on column public.usuario_papeis.setor_id is
  'Nulo em papel global; obrigatorio em papel de escopo setor. Conferido por trigger contra public.papeis, nao por check, para que papel novo entre sem alterar constraint.';
comment on column public.usuario_papeis.fim is
  'Encerramento. Nada e apagado: revogar papel e preencher fim. A acao alterarPapel chama auth.admin.signOut global para o token nao ficar valendo ate a renovacao.';
comment on column public.usuario_papeis.motivo is
  'Referencia da ata ou da decisao que nomeou. E o que liga a concessao ao ato institucional.';

create table if not exists public.delegacoes (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid not null references public.workspaces (id) on delete cascade,
  delegante_id  uuid not null references public.profiles (id) on delete cascade,
  delegado_id   uuid not null references public.profiles (id) on delete cascade,
  papel         text not null references public.papeis (slug) on delete restrict,
  setor_id      uuid references public.setores (id) on delete restrict,
  inicio        timestamptz not null default now(),
  fim           timestamptz,
  motivo        text,
  criado_por    uuid references public.profiles (id) on delete set null,
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  constraint delegacoes_pessoas_distintas check (delegante_id <> delegado_id),
  constraint delegacoes_fim_posterior     check (fim is null or fim >= inicio)
);

create index if not exists delegacoes_delegante_id_idx on public.delegacoes (delegante_id);
create index if not exists delegacoes_delegado_id_idx  on public.delegacoes (delegado_id);
create index if not exists delegacoes_setor_id_idx     on public.delegacoes (setor_id);
create index if not exists delegacoes_vigentes_idx
  on public.delegacoes (delegado_id, papel, setor_id) where fim is null;

drop trigger if exists delegacoes_tocar on public.delegacoes;
create trigger delegacoes_tocar before update on public.delegacoes
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists delegacoes_escopo on public.delegacoes;
create trigger delegacoes_escopo before insert or update on public.delegacoes
  for each row execute function public.validar_escopo_do_papel();

comment on table public.delegacoes is
  'Delegacao por ausencia: delegante, delegado, papel, setor e vigencia. Da Delega com inizio e fine do Jorvik, mais a redistribuicao de tarefas por ausencia do e-ARQ Brasil 2. O delegado continua sujeito a regra de conflito de interesse: quem pediu nunca decide, nem por delegacao. A RPC decidir_autorizacao (parte 4) grava a delegacao usada em autorizacao_decisoes.delegacao_id.';
comment on column public.delegacoes.fim is
  'Encerramento da delegacao. Delegacao vencida nao e apagada: fica no historico e no evento delegacao.encerrada da trilha.';


-- ============================================================
-- 12. Convites
--
-- Unico caminho de entrada para e-mail fora do dominio institucional.
-- O token em claro so viaja no e-mail; aqui fica o SHA-256 dele.
-- ============================================================

create table if not exists public.convites (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid not null references public.workspaces (id) on delete cascade,
  email         text not null check (position('@' in email) > 1),
  tipo_vinculo  text not null check (tipo_vinculo in ('colaborador','voluntario','instrutor','parceiro_externo','diretoria')),
  setor_id      uuid references public.setores (id) on delete restrict,
  papel_inicial text references public.papeis (slug) on delete restrict,
  token_hash    text not null check (token_hash ~ '^[0-9a-f]{64}$'),
  criado_por    uuid not null references public.profiles (id) on delete restrict,
  expira_em     timestamptz not null default now() + interval '14 days',
  aceito_em     timestamptz,
  aceito_por    uuid references public.profiles (id) on delete set null,
  revogado_em   timestamptz,
  mensagem      text,
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  constraint convites_aceite_coerente check ((aceito_em is null) = (aceito_por is null)),
  constraint convites_nao_aceito_e_revogado check (aceito_em is null or revogado_em is null)
);

create unique index if not exists convites_token_hash_idx on public.convites (token_hash);
create index if not exists convites_setor_id_idx   on public.convites (setor_id);
create index if not exists convites_criado_por_idx on public.convites (criado_por);
create unique index if not exists convites_aberto_idx
  on public.convites (workspace_id, lower(email))
  where aceito_em is null and revogado_em is null;

drop trigger if exists convites_tocar on public.convites;
create trigger convites_tocar before update on public.convites
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists convites_normalizar_email on public.convites;
create trigger convites_normalizar_email before insert or update on public.convites
  for each row execute function public.normalizar_email_convite();

comment on table public.convites is
  'Convite nominal com validade de 14 dias. Unico caminho de entrada para e-mail fora do dominio institucional. O e-mail sai por rota da intranet pelo Resend, e nao por inviteUserByEmail do Supabase, para que o texto, o remetente e o contador diario fiquem sob controle da casa. anon nunca le a tabela: a rota /convite/[token] resolve por public.consultar_convite(), que devolve so e-mail mascarado e validade.';
comment on column public.convites.email is
  'dado_pessoal | e-mail do convidado, normalizado em minusculas por trigger e por indice.';
comment on column public.convites.token_hash is
  'SHA-256 em 64 hexadecimais do token enviado por e-mail. O token em claro nunca e guardado: o que nao esta no banco nao vaza.';
comment on column public.convites.papel_inicial is
  'Papel concedido no aceite, opcional. Papel com exige_mfa so por administrador ou secretaria; coordenador convida para o proprio setor e so com tipo_vinculo voluntario ou parceiro_externo.';
comment on column public.convites.revogado_em is
  'Revogacao. Convite aceito nao pode ser reutilizado e convite revogado nao pode ser aceito, garantido por check e pela funcao de aceite.';


-- ============================================================
-- 12.1 Codigos de recuperacao do segundo fator
--
-- A tabela nasce com RLS ligada e sem policy nenhuma para authenticated: nem
-- select, nem insert, nem delete. Os dez codigos sao gerados na inscricao do
-- fator por public.gerar_codigos_recuperacao(), que grava apenas o hash, e
-- conferidos por public.usar_codigo_recuperacao(), que marca usado_em e nunca
-- devolve o codigo. As duas funcoes security definer sao a unica porta, por
-- isso o enable row level security vem junto da tabela e nao na secao 19.
-- ============================================================

create table if not exists public.codigos_recuperacao (
  id           uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  profile_id   uuid not null references public.profiles (id) on delete cascade,
  hash         text not null check (hash ~ '^[0-9a-f]{64}$'),
  usado_em     timestamptz,
  criado_em    timestamptz not null default now()
);

create index if not exists codigos_recuperacao_profile_id_idx on public.codigos_recuperacao (profile_id);
create unique index if not exists codigos_recuperacao_nao_usado_idx
  on public.codigos_recuperacao (profile_id, hash) where usado_em is null;

alter table public.codigos_recuperacao enable row level security;

revoke all on table public.codigos_recuperacao from public, anon, authenticated;

create or replace function public.gerar_codigos_recuperacao()
returns setof text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_workspace uuid;
  v_codigo    text;
begin
  select v.workspace_id into v_workspace
    from public.vinculos v
   where v.profile_id = (select auth.uid())
   order by case v.estado when 'active' then 0 when 'new' then 1 else 2 end, v.inicio desc
   limit 1;

  if v_workspace is null then
    select w.id into v_workspace from public.workspaces w where w.kind = 'production' limit 1;
  end if;

  if v_workspace is null then
    raise exception 'codigos de recuperacao: espaco nao resolvido para quem esta logado';
  end if;

  for i in 1..10 loop
    v_codigo := encode(extensions.gen_random_bytes(5), 'hex');
    insert into public.codigos_recuperacao (workspace_id, profile_id, hash)
    values (v_workspace, (select auth.uid()),
            encode(sha256(convert_to(v_codigo, 'UTF8')), 'hex'));
    return next v_codigo;
  end loop;
end;
$$;

create or replace function public.usar_codigo_recuperacao(p_codigo text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_id uuid;
begin
  select c.id into v_id
    from public.codigos_recuperacao c
   where c.profile_id = (select auth.uid())
     and c.usado_em is null
     and c.hash = encode(sha256(convert_to(p_codigo, 'UTF8')), 'hex')
   limit 1;

  if v_id is null then
    return false;
  end if;

  update public.codigos_recuperacao set usado_em = now() where id = v_id;
  return true;
end;
$$;

revoke all on function public.gerar_codigos_recuperacao()      from public, anon;
revoke all on function public.usar_codigo_recuperacao(text)    from public, anon;
grant execute on function public.gerar_codigos_recuperacao()   to authenticated;
grant execute on function public.usar_codigo_recuperacao(text) to authenticated;

comment on table public.codigos_recuperacao is
  'Dez codigos de reserva por pessoa para recuperar o segundo fator, guardados so em SHA-256. Existe porque o Supabase nao emite codigos de reserva e a recuperacao de fator hoje depende do administrador, papel limitado a duas pessoas. Sem policy para authenticated: as duas funcoes security definer sao a unica porta, e o codigo em claro so existe na tela que o gerou.';
comment on column public.codigos_recuperacao.hash is
  'SHA-256 em 64 hexadecimais do codigo. O codigo em claro nunca e guardado: o que nao esta no banco nao vaza.';
comment on column public.codigos_recuperacao.usado_em is
  'Marcado por public.usar_codigo_recuperacao(). Codigo usado nao e apagado: fica como evidencia de que a recuperacao aconteceu.';
comment on function public.gerar_codigos_recuperacao() is
  'Gera os dez codigos na inscricao do fator, grava apenas o hash e devolve os codigos em claro uma unica vez, para a tela mostrar. gen_random_bytes vem da pgcrypto; o hash usa o sha256 nativo do Postgres 17.';
comment on function public.usar_codigo_recuperacao(text) is
  'Confere o codigo contra o hash da propria pessoa, marca usado_em e devolve so verdadeiro ou falso. Nunca devolve o codigo nem diz quantos restam.';


-- ============================================================
-- 13. Formacao, credencial e termo de adesao
--
-- Existem porque o vinculo depende delas, nao como cadastro de voluntariado:
-- catalogo de cursos, escala, horas e disponibilidade ficam fora desta rodada.
-- documento_id e comprovante_documento_id ficam sem chave estrangeira aqui de
-- proposito: public.documentos nasce na parte da biblioteca, e a chave que
-- fecharia o ciclo entre partes entra em migracao propria, depois das duas.
-- ============================================================

create table if not exists public.formacoes (
  id                      uuid primary key default gen_random_uuid(),
  workspace_id            uuid not null references public.workspaces (id) on delete cascade,
  profile_id              uuid not null references public.profiles (id) on delete cascade,
  tipo                    text not null check (tipo in ('cbfi','primeiros_socorros','curso_interno','externa')),
  nome                    text not null,
  instituicao             text,
  concluida_em            date,
  validade_ate            date,
  comprovante_documento_id uuid,
  hash_comprovante        text check (hash_comprovante is null or hash_comprovante ~ '^[0-9a-f]{64}$'),
  verificado_por          uuid references public.profiles (id) on delete set null,
  verificado_em           timestamptz,
  criado_em               timestamptz not null default now(),
  atualizado_em           timestamptz not null default now(),
  constraint formacoes_verificacao_coerente check ((verificado_por is null) = (verificado_em is null))
);

create index if not exists formacoes_profile_id_idx  on public.formacoes (profile_id);
create index if not exists formacoes_documento_id_idx on public.formacoes (comprovante_documento_id);
create index if not exists formacoes_vencendo_idx    on public.formacoes (workspace_id, validade_ate)
  where validade_ate is not null;

drop trigger if exists formacoes_tocar on public.formacoes;
create trigger formacoes_tocar before update on public.formacoes
  for each row execute function public.tocar_atualizado_em();

comment on table public.formacoes is
  'So as formacoes que condicionam a adesao (CBFI, primeiros socorros e registro de curso interno ou externo ja feito). Nao e catalogo de cursos nem historico de aluno, que estao fora desta rodada. Existe porque vinculos.estado so vai a active com a formacao obrigatoria registrada e verificada, como no fluxo de adesao da filial MG. Referencias: Activity e custom fields de formacao do VDMS da IFRC sobre CiviCRM.';
comment on column public.formacoes.comprovante_documento_id is
  'Aponta para public.documentos, da parte da biblioteca. Sem chave estrangeira nesta migracao: a chave entre partes entra em migracao propria, depois das duas tabelas.';
comment on column public.formacoes.hash_comprovante is
  'SHA-256 do comprovante, mantido depois da eliminacao do binario. E o que permite conferir a formacao quando o arquivo ja nao existe.';
comment on column public.formacoes.verificado_por is
  'Instrutor ou Secretaria que validou (permissao pessoa.confirmar_vinculo). Formacao nao verificada nao habilita o vinculo a active.';

create table if not exists public.credenciais (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid not null references public.workspaces (id) on delete cascade,
  profile_id    uuid not null references public.profiles (id) on delete cascade,
  tipo          text not null check (tipo in ('carteirinha','registro_profissional','seguro','outra')),
  numero        text,
  emissor       text,
  validade_ate  date,
  status        text not null default 'valid' check (status in ('valid','expired','revoked')),
  documento_id  uuid,
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now()
);

create index if not exists credenciais_profile_id_idx on public.credenciais (profile_id);
create index if not exists credenciais_documento_id_idx on public.credenciais (documento_id);
create index if not exists credenciais_vigentes_idx on public.credenciais (workspace_id, validade_ate)
  where status = 'valid';

drop trigger if exists credenciais_tocar on public.credenciais;
create trigger credenciais_tocar before update on public.credenciais
  for each row execute function public.tocar_atualizado_em();

comment on table public.credenciais is
  'Credenciais com validade ligadas a atuacao: carteirinha de voluntario, registro profissional, seguro. Do Documento (tipo, expires) e do Tesserino do Jorvik. Existe porque o tramite e a biblioteca precisam saber se a credencial estava vigente na data do ato; nao e cadastro de disponibilidade, escala ou horas.';
comment on column public.credenciais.numero is
  'dado_pessoal | numero da credencial. Em registro profissional, o conselho e a UF vao em emissor.';
comment on column public.credenciais.status is
  'Ciclo de vida, em ingles: valid, expired, revoked. Credencial nao e apagada; revogar e update de status.';
comment on column public.credenciais.documento_id is
  'Aponta para public.documentos, da parte da biblioteca. Chave estrangeira em migracao posterior.';

create table if not exists public.termos_adesao (
  id                     uuid primary key default gen_random_uuid(),
  workspace_id           uuid not null references public.workspaces (id) on delete cascade,
  profile_id             uuid not null references public.profiles (id) on delete cascade,
  vinculo_id             uuid references public.vinculos (id) on delete set null,
  modelo_versao          text not null,
  documento_id           uuid,
  hash_pdf               text check (hash_pdf is null or hash_pdf ~ '^[0-9a-f]{64}$'),
  nivel_assinatura       public.nivel_assinatura not null default 'nenhuma',
  assinado_em            timestamptz,
  status                 text not null default 'pending' check (status in ('pending','signed','revoked','expired')),
  revogado_em            timestamptz,
  responsavel_profile_id uuid references public.profiles (id) on delete set null,
  criado_em              timestamptz not null default now(),
  atualizado_em          timestamptz not null default now(),
  constraint termos_adesao_assinado_com_hash
    check (status <> 'signed' or (hash_pdf is not null and assinado_em is not null)),
  constraint termos_adesao_revogado_com_data
    check (status <> 'revoked' or revogado_em is not null)
);

create index if not exists termos_adesao_profile_id_idx on public.termos_adesao (profile_id);
create index if not exists termos_adesao_vinculo_id_idx on public.termos_adesao (vinculo_id);
create index if not exists termos_adesao_documento_id_idx on public.termos_adesao (documento_id);
create unique index if not exists termos_adesao_vigente_idx
  on public.termos_adesao (profile_id, vinculo_id) nulls not distinct
  where status = 'signed';

drop trigger if exists termos_adesao_tocar on public.termos_adesao;
create trigger termos_adesao_tocar before update on public.termos_adesao
  for each row execute function public.tocar_atualizado_em();

comment on table public.termos_adesao is
  'Indice por pessoa e por vinculo do termo da Lei 9.608/1998 (art. 2): versao do modelo, documento gerado, hash do PDF, nivel de assinatura aplicado, data e revogacao. E o fato do vinculo; o arquivo mora em public.documentos. O padrao de evidencia por documento vem do DocumentAuditLog do Documenso.';
comment on column public.termos_adesao.modelo_versao is
  'Versao do modelo usado, de public.modelos_documento (parte da biblioteca). So modelo com status approved gera termo valido.';
comment on column public.termos_adesao.hash_pdf is
  'SHA-256 do PDF assinado. Sobrevive a eliminacao do binario: ao fim da retencao o documento_id e anulado e o hash fica.';
comment on column public.termos_adesao.status is
  'Ciclo de vida, em ingles: pending, signed, revoked, expired. Voluntario so vai a vinculos.estado = active com termo signed.';
comment on column public.termos_adesao.responsavel_profile_id is
  'Responsavel legal quando a pessoa tem de 16 a 18 anos (Membro Juvenil do Estatuto). Coluna prevista; o fluxo de dupla assinatura e decisao pendente e fica fora desta rodada.';


-- ============================================================
-- 14. Governanca: decisoes da Diretoria e politica de assinatura
-- ============================================================

create table if not exists public.decisoes_institucionais (
  id                 uuid primary key default gen_random_uuid(),
  workspace_id       uuid not null references public.workspaces (id) on delete cascade,
  codigo             text not null check (codigo ~ '^D[0-9]{2}$'),
  titulo             text not null,
  opcao_recomendada  text not null,
  opcao_escolhida    text,
  status             text not null default 'pending' check (status in ('pending','decided','revised')),
  decidido_em        timestamptz,
  decidido_por       uuid references public.profiles (id) on delete set null,
  documento_anexo_id uuid,
  revisao_em         date,
  criado_em          timestamptz not null default now(),
  atualizado_em      timestamptz not null default now(),
  constraint decisoes_institucionais_decidida_completa
    check (status <> 'decided' or (opcao_escolhida is not null and decidido_em is not null))
);

-- Parcial: revisao nunca altera a linha, cria linha nova com o mesmo codigo e
-- a anterior passa a revised. So pode haver um codigo vigente por espaco.
create unique index if not exists decisoes_institucionais_codigo_idx
  on public.decisoes_institucionais (workspace_id, codigo)
  where status <> 'revised';
create index if not exists decisoes_institucionais_decidido_por_idx on public.decisoes_institucionais (decidido_por);
create index if not exists decisoes_institucionais_anexo_idx on public.decisoes_institucionais (documento_anexo_id);
create index if not exists decisoes_institucionais_revisao_idx on public.decisoes_institucionais (workspace_id, revisao_em)
  where revisao_em is not null;

drop trigger if exists decisoes_institucionais_tocar on public.decisoes_institucionais;
create trigger decisoes_institucionais_tocar before update on public.decisoes_institucionais
  for each row execute function public.tocar_atualizado_em();

comment on table public.decisoes_institucionais is
  'Registro das decisoes da Diretoria D01 a D12 e das suas revisoes, com opcao recomendada, opcao escolhida, data, responsavel, anexo na biblioteca e data da proxima revisao. A fase 0 nao fecha sem as doze linhas decididas. Substitui o nome institutional_decisions. A ideia de deliberacao com prazo e registro vem do DRK Rundlaufbeschluesse (MIT), so como referencia de desenho.';
comment on column public.decisoes_institucionais.status is
  'Ciclo de vida, em ingles: pending, decided, revised. Revisao nunca altera a linha: cria linha nova e a anterior fica revised, o que preserva o historico da deliberacao.';
comment on column public.decisoes_institucionais.documento_anexo_id is
  'Parecer ou oficio anexado na biblioteca. Aponta para public.documentos; chave estrangeira em migracao posterior.';
comment on column public.decisoes_institucionais.revisao_em is
  'Proxima revisao. E o que faz a rotacao anual da chave da filial (D09) aparecer como tarefa e nao como esquecimento.';

create table if not exists public.politicas_assinatura (
  id              uuid primary key default gen_random_uuid(),
  workspace_id    uuid not null references public.workspaces (id) on delete cascade,
  tipo_ato        public.tipo_ato not null,
  nivel_exigido   public.nivel_assinatura not null,
  exige_mfa       boolean not null default true,
  decisao_id      uuid references public.decisoes_institucionais (id) on delete restrict,
  vigencia_inicio date not null default current_date,
  criado_em       timestamptz not null default now()
);

create unique index if not exists politicas_assinatura_vigencia_idx
  on public.politicas_assinatura (workspace_id, tipo_ato, vigencia_inicio);
create index if not exists politicas_assinatura_decisao_id_idx on public.politicas_assinatura (decisao_id);
create index if not exists politicas_assinatura_busca_idx
  on public.politicas_assinatura (workspace_id, tipo_ato, vigencia_inicio desc);

comment on table public.politicas_assinatura is
  'Fonte normativa unica de qual nivel da Lei 14.063/2020 cada tipo de ato exige, decidida em D04. Nenhuma outra tabela repete essa regra: autorizacao_regras aponta para ca e autorizacoes congela o valor na submissao. Substitui o nome signature_policies. Bloco de assinatura por tipo de documento do SEI.';
comment on column public.politicas_assinatura.vigencia_inicio is
  'Mudanca de politica nao altera a linha: cria linha nova com vigencia posterior, e a anterior deixa de valer. O ato ja submetido guarda o nivel congelado.';
comment on column public.politicas_assinatura.exige_mfa is
  'Reautenticacao com MFA TOTP (claim aal2) no aceite interno. Conferido por private.exige_aal2() nas policies de decisao.';


-- ============================================================
-- 15. Schema operacao
--
-- Leitura so por administrador e auditor; escrita por job ou por funcao
-- security definer. Nao ha policy de insert para authenticated.
-- ============================================================

create table if not exists operacao.backups (
  id                      uuid primary key default gen_random_uuid(),
  executado_em            timestamptz not null default now(),
  origem                  text not null check (origem in ('github_actions','manual','custodia')),
  dump_bytes              bigint not null default 0,
  objetos_copiados        integer not null default 0,
  versoes_cobertas        integer not null default 0,
  versoes_faltando        integer not null default 0,
  destino                 text not null,
  hash_dump               text check (hash_dump is null or hash_dump ~ '^[0-9a-f]{64}$'),
  ok                      boolean not null default false,
  erro                    text,
  restauracao_testada_em  timestamptz,
  restauracao_duracao_s   integer,
  restauracao_cadeia_ok   boolean
);

create index if not exists backups_executado_em_idx on operacao.backups (executado_em desc);
create index if not exists backups_restauracao_idx  on operacao.backups (restauracao_testada_em desc)
  where restauracao_testada_em is not null;

comment on table operacao.backups is
  'Registro de cada dump e copia de storage do job diario e de cada teste de restauracao, para que a tela de operacao e a rota /api/admin/backup-check mostrem o estado real sem tocar no destino. Sem workspace_id: o backup e do projeto inteiro. Nivel 0.5 da pesquisa de rastreabilidade: hash encadeado detecta, backup recupera. O job passa a cobrir tambem os binarios da biblioteca nos tres destinos possiveis de public.documento_versoes.storage_backend: versoes_cobertas e versoes_faltando contam as versoes vigentes e nao eliminadas com e sem copia no destino, e o job falha enquanto versoes_faltando for maior que zero.';
comment on column operacao.backups.origem is
  'De onde veio a copia: github_actions e o job diario, manual e a execucao avulsa e custodia registra a copia mensal cifrada entregue a Diretoria em midia fisica, que existe enquanto nao houver doze meses de pagamento regular dos planos.';
comment on column operacao.backups.destino is
  'Nome logico do destino, nunca URL com credencial. Valor de credencial nao entra em tabela, em log nem em rota.';
comment on column operacao.backups.restauracao_cadeia_ok is
  'Resultado de auditoria.verificar_cadeia() contra o dump restaurado. E o que prova backup e cadeia juntos no teste trimestral.';

create table if not exists operacao.fila_emails (
  id             uuid primary key default gen_random_uuid(),
  workspace_id   uuid not null references public.workspaces (id) on delete cascade,
  destinatario_id uuid not null references public.profiles (id) on delete cascade,
  notificacao_id uuid references public.notifications (id) on delete set null,
  tipo           text not null,
  entidade_tipo  text,
  entidade_id    uuid,
  prioridade     text not null default 'resumo' check (prioridade in ('imediato','resumo','nenhum')),
  status         text not null default 'queued' check (status in ('queued','sent','suppressed','failed')),
  lote_id        uuid,
  criado_em      timestamptz not null default now(),
  enviado_em     timestamptz,
  erro           text
);

create index if not exists fila_emails_destinatario_idx on operacao.fila_emails (destinatario_id);
create index if not exists fila_emails_notificacao_idx  on operacao.fila_emails (notificacao_id);
create index if not exists fila_emails_lote_idx         on operacao.fila_emails (lote_id);
create index if not exists fila_emails_pendentes_idx
  on operacao.fila_emails (workspace_id, prioridade, criado_em) where status = 'queued';

comment on table operacao.fila_emails is
  'Fila unica de notificacao por e-mail, com prioridade e agrupamento em digest. E o unico lugar que decide entrega: public.notifications cuida do sino e nao guarda nada sobre e-mail. E-mail de autenticacao (codigo e convite) sai direto pelo SMTP do Auth no Resend e nunca entra na fila, para nao competir com a reserva de notificacoes.';
comment on column operacao.fila_emails.destinatario_id is
  'Referencia a pessoa, nunca o e-mail em claro: endereco na fila e lista de e-mail esperando para vazar.';
comment on column operacao.fila_emails.tipo is
  'Codigo do evento, do catalogo tipo_notificacao (aviso.publicado, autorizacao.pendente, grupo.convite). Em portugues porque e vocabulario institucional, nao ciclo de vida.';
comment on column operacao.fila_emails.prioridade is
  'So aviso.publicado com prioridade urgente, autorizacao.pendente do aprovador e grupo.convite sao imediato. O resto vai no digest.';
comment on column operacao.fila_emails.status is
  'Ciclo de vida, em ingles: queued, sent, suppressed, failed. suppressed e o que o orcamento diario recusou.';

create table if not exists operacao.orcamento_emails (
  dia                    date not null,
  workspace_id           uuid not null references public.workspaces (id) on delete cascade,
  reserva_autenticacao   integer not null default 40,
  reserva_notificacoes   integer not null default 50,
  reserva_folga          integer not null default 10,
  gasto_autenticacao     integer not null default 0,
  gasto_notificacoes     integer not null default 0,
  gasto_folga            integer not null default 0,
  digest_suprimido       boolean not null default false,
  criado_em              timestamptz not null default now(),
  atualizado_em          timestamptz not null default now(),
  primary key (dia, workspace_id)
);

create index if not exists orcamento_emails_dia_idx on operacao.orcamento_emails (workspace_id, dia desc);

drop trigger if exists orcamento_emails_tocar on operacao.orcamento_emails;
create trigger orcamento_emails_tocar before update on operacao.orcamento_emails
  for each row execute function public.tocar_atualizado_em();

comment on table operacao.orcamento_emails is
  'Uma linha por dia com a reserva e o gasto de cada bolso do orcamento do Resend gratuito (100 por dia, 3.000 por mes): autenticacao, notificacoes e folga. Colapsa em uma so tabela os tres nomes divergentes que os blocos propunham (operacao.emails_dia, email_orcamento e um contador solto). E o que a rota de digest consulta antes de enviar.';
comment on column operacao.orcamento_emails.reserva_autenticacao is
  'Reserva do dia para codigo de login e convite. Autenticacao tem prioridade: sem codigo ninguem entra, e notificacao atrasada nao impede ninguem de trabalhar.';
comment on column operacao.orcamento_emails.digest_suprimido is
  'true quando o teto do dia foi alcancado e o digest da tarde ficou para o dia seguinte. Tres dias assim em sete e o gatilho do Resend Pro.';

create table if not exists operacao.uso_plano (
  dia             date not null,
  metrica         text not null check (metrica in (
                    'emails_enviados','egress_gb','disco_gb','downloads_privados',
                    'upload_recusado_tamanho','assinaturas_govbr','signatario_sem_govbr',
                    'conexoes_realtime_pico','ponte_auditoria_falhou','login_iniciado',
                    'login_concluido')),
  workspace_id    uuid not null references public.workspaces (id) on delete cascade,
  valor           numeric not null default 0,
  limite          numeric,
  acima_do_limite boolean not null default false,
  origem          text not null default 'automatico' check (origem in ('automatico','manual')),
  observacao      text,
  registrado_em   timestamptz not null default now(),
  primary key (workspace_id, dia, metrica)
);

create index if not exists uso_plano_metrica_idx on operacao.uso_plano (workspace_id, metrica, dia desc);
create index if not exists uso_plano_gatilhos_idx on operacao.uso_plano (workspace_id, dia desc) where acima_do_limite;

comment on table operacao.uso_plano is
  'Serie diaria das metricas que disparam os gatilhos de upgrade: e-mails, egress, disco, downloads privados, upload recusado por tamanho, assinaturas gov.br, signatario sem conta gov.br e pico de conexoes Realtime. Absorve a usage_snapshots proposta no bloco de contexto, que era duplicata. A decisao de subir de plano passa a ser por dado e nao por susto.';
comment on column operacao.uso_plano.metrica is
  'Vocabulario institucional, em portugues. Cada valor corresponde a um gatilho escrito no plano de operacao. ponte_auditoria_falhou conta as falhas do trigger de ponte do public.activity_log, que passa a engolir excecao para nunca derrubar escrita da Redacao e por isso precisa deixar rastro visivel na tela de operacao; login_iniciado e login_concluido medem o abandono no funil de entrada por codigo de seis digitos, que e o numero que decide se os limiares de leitura do mural sao aplicaveis.';
comment on column operacao.uso_plano.origem is
  'automatico quando o app calcula; manual quando o numero e copiado do painel do provedor, que ainda nao expoe API.';

create table if not exists operacao.limite_taxa (
  chave         text not null,
  janela_inicio timestamptz not null,
  contagem      integer not null default 1,
  primary key (chave, janela_inicio)
);

create index if not exists limite_taxa_janela_idx on operacao.limite_taxa (janela_inicio);

comment on table operacao.limite_taxa is
  'Contador por janela usado por operacao.permitir() para limitar taxa nas rotas publicas sem servico externo: o Postgres e o unico armazenamento compartilhado entre funcoes da Vercel sem custo novo. Sem workspace_id: a chamada e anterior a sessao. Nenhuma role recebe grant direto aqui.';
comment on column operacao.limite_taxa.chave is
  'SHA-256 de rota mais IP, calculado na borda. Nunca IP em claro: o limite de taxa nao pode virar um registro de quem visitou o que.';


-- ============================================================
-- 16. Funcoes auxiliares de RLS no schema private
--
-- Padrao da Redacao (20260820183812): security definer para quebrar a
-- recursao de RLS, search_path vazio, stable, e cada uma respondendo apenas
-- sobre auth.uid(). As policies as chamam embrulhadas em (select ...).
-- As funcoes existentes da Redacao (is_workspace_member, workspace_role,
-- shares_workspace, pauta_workspace, content_workspace) continuam valendo e
-- nao sao alteradas por esta migracao.
-- ============================================================

-- MFA TOTP: reescrita de authenticative.is_user_authenticated() do template
-- Razikus (Apache-2.0, 20250107210416_MFA.sql), com a licao do issue 4 do
-- proprio Razikus: nao escrever no schema auth. Aqui a exigencia e estrita, e
-- nao a variante tolerante do original: quem recebe papel com exige_mfa
-- cadastra o fator antes de decidir, e a tela /conta/seguranca cobra isso.
create or replace function private.exige_aal2()
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select coalesce((select auth.jwt() ->> 'aal'), '') = 'aal2';
$$;

create or replace function private.vinculo_ativo()
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.vinculos v
    where v.profile_id = (select auth.uid())
      and v.estado = 'active'
      and (v.fim is null or v.fim > now())
  );
$$;

create or replace function private.pertence_ao_espaco(p_workspace_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.workspace_members wm
    where wm.user_id = (select auth.uid())
      and wm.workspace_id = p_workspace_id
  ) or exists (
    select 1 from public.vinculos v
    where v.profile_id = (select auth.uid())
      and v.workspace_id = p_workspace_id
      and v.estado <> 'terminated'
      and (v.fim is null or v.fim > now())
  );
$$;

-- Privilegio junto da definicao, no mesmo padrao da secao 21: funcao de
-- private nunca fica executavel por public nem por anon.
revoke all on function private.pertence_ao_espaco(uuid) from public, anon;
grant execute on function private.pertence_ao_espaco(uuid) to authenticated;

create or replace function private.setor_do_usuario()
returns uuid
language sql
security definer
stable
set search_path = ''
as $$
  select coalesce(
    (select v.setor_id from public.vinculos v
       where v.profile_id = (select auth.uid())
         and v.estado = 'active'
         and (v.fim is null or v.fim > now())
         and v.setor_id is not null
       order by v.inicio desc limit 1),
    (select s.id from public.workspace_members wm
       join public.setores s on s.slug = wm.coordination and s.ativo
      where wm.user_id = (select auth.uid()) limit 1)
  );
$$;

create or replace function private.mesmo_setor(p_profile_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.vinculos meu
    join public.vinculos outro on outro.setor_id = meu.setor_id
    where meu.profile_id = (select auth.uid())
      and meu.setor_id is not null
      and meu.estado = 'active' and (meu.fim is null or meu.fim > now())
      and outro.profile_id = p_profile_id
      and outro.estado = 'active' and (outro.fim is null or outro.fim > now())
  );
$$;

create or replace function private.pertence_ao_setor(p_setor_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.vinculos v
    where v.profile_id = (select auth.uid())
      and v.setor_id = p_setor_id
      and v.estado = 'active'
      and (v.fim is null or v.fim > now())
  );
$$;

revoke all on function private.pertence_ao_setor(uuid) from public, anon;
grant execute on function private.pertence_ao_setor(uuid) to authenticated;

create or replace function private.papel_global()
returns text
language sql
security definer
stable
set search_path = ''
as $$
  select coalesce(
    (select up.papel
       from public.usuario_papeis up
       join public.papeis p on p.slug = up.papel and p.ativo
      where up.user_id = (select auth.uid())
        and up.inicio <= now()
        and (up.fim is null or up.fim > now())
      order by p.alcance desc
      limit 1),
    (select case wm.role
              when 'admin'       then 'administrador'
              when 'editor'      then 'comunicacao'
              when 'colaborador' then 'colaborador'
            end
       from public.workspace_members wm
      where wm.user_id = (select auth.uid())
      limit 1)
  );
$$;

create or replace function private.tem_papel(p_papel text, p_setor_id uuid default null)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.usuario_papeis up
    join public.papeis p on p.slug = up.papel and p.ativo
    where up.user_id = (select auth.uid())
      and up.papel = p_papel
      and up.inicio <= now()
      and (up.fim is null or up.fim > now())
      and (
        (p_setor_id is null and up.setor_id is null)
        or (p_setor_id is not null and (up.setor_id is null or up.setor_id = p_setor_id))
      )
  );
$$;

comment on function private.exige_aal2() is
  'Verdadeiro so com sessao aal2, isto e, MFA TOTP verificada. Reescrita de authenticative.is_user_authenticated() do Razikus (Apache-2.0), sem escrever no schema auth. Entra no with check de toda escrita de decisao: autorizacao_decisoes, assinaturas, usuario_papeis, mudanca de nivel de acesso de documento, publicacao de aviso oficial, aprovacao de modelo e concessao de credencial nominal de sigiloso.';
comment on function private.vinculo_ativo() is
  'Verdadeiro quando quem esta logado tem vinculo com estado active vigente. Ninguem aparece no diretorio nem publica antes disso.';
comment on function private.pertence_ao_espaco(uuid) is
  'Pertencimento ao espaco na intranet: linha em public.workspace_members ou vinculo em public.vinculos naquele espaco com estado diferente de terminated e ainda vigente. Existe porque vinculos passou a ser a fonte de pertencimento da intranet e workspace_members deixou de ser pre-requisito de acesso: nenhum caminho de entrada de voluntario cria linha nela. private.is_workspace_member continua existindo, sem alteracao, para as tabelas editoriais da Redacao.';
comment on function private.setor_do_usuario() is
  'Setor da pessoa, na ordem: setor do vinculo com estado active mais recente e, por ultimo, workspace_members.coordination resolvida por setores.slug. Nao le mais public.profiles.setor_principal_id: a coluna e editavel pela propria pessoa e por isso nao pode ser prova de pertencimento a setor, embora continue valendo para exibicao e para a claim setor_principal do hook. O segundo degrau e a ponte de tolerancia enquanto a Redacao for a fonte do papel.';
comment on function private.mesmo_setor(uuid) is
  'Verdadeiro quando quem esta logado compartilha ao menos um setor de vinculo ativo com a pessoa consultada. E o que sustenta visibilidade_diretorio = setor. Responde sobre pessoa e serve apenas ao diretorio: passar um setor_id no lugar de um profile_id compila e devolve falso sempre, que foi o defeito encontrado nas partes de biblioteca e de autorizacao. Para perguntar sobre setor, private.pertence_ao_setor(uuid).';
comment on function private.pertence_ao_setor(uuid) is
  'Verdadeiro quando quem esta logado tem vinculo naquele setor com estado active e ainda vigente. Responde sobre setor; private.mesmo_setor(p_profile_id uuid) responde sobre pessoa.';
comment on function private.papel_global() is
  'Papel de maior alcance de quem esta logado, com a mesma tolerancia do hook de token: sem linha em usuario_papeis, le workspace_members.role e mapeia admin para administrador, editor para comunicacao e colaborador para colaborador.';
comment on function private.tem_papel(text, uuid) is
  'Usada so onde a permissao nomeada nao basta, por exemplo na exclusividade de conceder os papeis administrador e auditor. A regra normal e chamar public.autorizar().';

-- A funcao que toda policy chama em vez de consultar papeis. Copia ampliada do
-- authorize() do exemplo oficial slack-clone da Supabase: ganha o segundo
-- parametro de setor e um degrau de tolerancia. Semantica do setor: perguntar
-- sem setor e perguntar por permissao global; perguntar com setor aceita papel
-- global ou papel daquele setor, nunca de outro.
create or replace function public.autorizar(
  p_permissao public.permissao,
  p_setor_id  uuid default null
)
returns boolean
language plpgsql
security definer
stable
set search_path = ''
as $$
declare
  v_papeis jsonb;
  v_ok     boolean;
begin
  v_papeis := nullif((select auth.jwt() -> 'papeis'), 'null'::jsonb);

  if v_papeis is not null
     and jsonb_typeof(v_papeis) = 'array'
     and jsonb_array_length(v_papeis) > 0
  then
    select exists (
      select 1
      from jsonb_to_recordset(v_papeis) as c(papel text, setor_id uuid)
      join public.papel_permissoes pp
        on pp.papel = c.papel and pp.permissao = p_permissao
      where (p_setor_id is null and c.setor_id is null)
         or (p_setor_id is not null and (c.setor_id is null or c.setor_id = p_setor_id))
    ) into v_ok;
    return coalesce(v_ok, false);
  end if;

  -- Tolerancia: enquanto o hook de token nao tiver emitido a claim papeis
  -- (sessao antiga, hook desligado no painel, ou o bloco de excecao do hook
  -- tendo devolvido o evento intacto), a resposta vem do banco. Sem isto, um
  -- erro no hook viraria perda silenciosa de permissao para todo mundo.
  select exists (
    select 1
    from public.usuario_papeis up
    join public.papeis pa on pa.slug = up.papel and pa.ativo
    join public.papel_permissoes pp on pp.papel = up.papel and pp.permissao = p_permissao
    where up.user_id = (select auth.uid())
      and up.inicio <= now()
      and (up.fim is null or up.fim > now())
      and (
        (p_setor_id is null and up.setor_id is null)
        or (p_setor_id is not null and (up.setor_id is null or up.setor_id = p_setor_id))
      )
  ) into v_ok;
  return coalesce(v_ok, false);
end;
$$;

comment on function public.autorizar(public.permissao, uuid) is
  'Autorizacao por permissao nomeada. Copia ampliada de public.authorize() do exemplo oficial slack-clone da Supabase (Apache-2.0), com um segundo parametro de setor. Le a claim papeis do JWT e, se ela nao existir, cai para public.usuario_papeis. Toda policy chama esta funcao em vez de consultar papeis, o que evita a recursao que a Redacao resolve com funcoes security definer em private.';

-- Rota publica /convite/[token]: resolve pelo hash e devolve o minimo. Nao
-- devolve o e-mail inteiro, o papel inicial nem quem convidou. Mesma excecao
-- declarada de verificar_codigo e consultar_pedido_titular: pagina publica le
-- por funcao security definer de retorno fixo, nunca por policy de anon.
create or replace function public.consultar_convite(p_token text)
returns table (
  email_mascarado text,
  tipo_vinculo    text,
  setor_nome      text,
  expira_em       timestamptz,
  valido          boolean
)
language sql
security definer
stable
set search_path = ''
as $$
  select
    left(c.email, 1) || '***' || substring(c.email from position('@' in c.email)),
    c.tipo_vinculo,
    s.nome,
    c.expira_em,
    (c.aceito_em is null and c.revogado_em is null and c.expira_em > now())
  from public.convites c
  left join public.setores s on s.id = c.setor_id
  where c.token_hash = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')
  limit 1;
$$;

comment on function public.consultar_convite(text) is
  'Leitura publica de convite pelo token em claro, que e conferido contra o SHA-256 guardado. Devolve so e-mail mascarado, tipo de vinculo, setor e validade. anon nunca le public.convites: esta funcao e a unica porta, e a rota que a chama passa por operacao.permitir().';

create or replace function operacao.permitir(
  p_chave  text,
  p_limite integer,
  p_janela interval default interval '1 hour'
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_segundos numeric;
  v_inicio   timestamptz;
  v_contagem integer;
begin
  v_segundos := extract(epoch from p_janela);
  v_inicio := to_timestamp(floor(extract(epoch from now()) / v_segundos) * v_segundos);

  insert into operacao.limite_taxa as l (chave, janela_inicio, contagem)
  values (p_chave, v_inicio, 1)
  on conflict (chave, janela_inicio) do update set contagem = l.contagem + 1
  returning l.contagem into v_contagem;

  return v_contagem <= p_limite;
end;
$$;

comment on function operacao.permitir(text, integer, interval) is
  'Limite de taxa por janela fixa para rotas publicas, sem servico externo. A chave e SHA-256 de rota mais IP, calculado na borda. Usada em /verificar/[codigo] (30 por hora), /privacidade/pedido (5 por dia) e /convite/[token]. Janelas com mais de 24 horas sao removidas por job. Alem do execute, a role chamadora precisa de usage no schema operacao: sem esse usage ela nao resolvia a funcao e o limite de taxa das rotas publicas simplesmente nao existia.';


-- ============================================================
-- 16.1 Novo usuario: perfil e vinculo
--
-- Trigger em auth.users descrito no escopo e ausente do modelo. Reescrita do
-- handle_new_user do exemplo oficial da Supabase: decide por dominio e por
-- convite, e nao por sufixo de e-mail; username pela parte local do e-mail, no
-- padrao split_part do Makerkit Lite. O corpo inteiro fica dentro de bloco de
-- excecao que devolve o controle sem erro, pela mesma razao do hook de token:
-- falha aqui nunca pode bloquear login.
-- ============================================================

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_email     text;
  v_dominio   text;
  v_base      text;
  v_username  text;
  v_nome      text;
  v_tipo      text;
  v_convite   public.convites%rowtype;
  v_workspace uuid;
  v_n         integer := 0;
begin
  v_email := lower(coalesce(new.email, ''));
  if v_email = '' then
    return new;
  end if;
  if exists (select 1 from public.profiles p where p.id = new.id) then
    return new;
  end if;

  v_dominio := split_part(v_email, '@', 2);

  select c.* into v_convite
    from public.convites c
   where c.email = v_email
     and c.aceito_em is null
     and c.revogado_em is null
     and c.expira_em > now()
   order by c.criado_em desc
   limit 1;

  -- username pela parte local do e-mail, reduzido ao que o check da coluna
  -- aceita e desempatado por sufixo numerico.
  v_base := regexp_replace(split_part(v_email, '@', 1), '[^a-z0-9._-]', '', 'g');
  if char_length(v_base) < 3 then
    v_base := 'pessoa';
  end if;
  v_base := left(v_base, 36);
  v_username := v_base;
  while exists (select 1 from public.profiles p where p.username = v_username) loop
    v_n := v_n + 1;
    v_username := v_base || v_n::text;
  end loop;

  v_nome := coalesce(
    nullif(new.raw_user_meta_data ->> 'full_name', ''),
    nullif(new.raw_user_meta_data ->> 'name', ''),
    split_part(v_email, '@', 1));

  -- D03: dominio institucional e equipe; convite valido entra como externo; o
  -- resto e voluntario.
  v_tipo := case
              when v_dominio = 'cruzvermelhariodejaneiro.org' then 'equipe'
              when v_convite.id is not null                   then 'externo'
              else 'voluntario'
            end;

  insert into public.profiles (id, username, full_name, initials, tipo_conta)
  values (new.id, v_username, v_nome, upper(left(v_username, 2)), v_tipo);

  -- Vinculo so para quem entra pelo dominio: quem entra por convite ganha o
  -- vinculo no aceite, pela acao aceitarConvite, e quem nao tem nem dominio
  -- nem convite fica sem vinculo e vai para /sem-vinculo.
  if v_tipo = 'equipe' then
    select w.id into v_workspace from public.workspaces w where w.kind = 'production' limit 1;
    if v_workspace is not null then
      insert into public.vinculos (workspace_id, profile_id, tipo, estado, origem)
      values (v_workspace, new.id, 'colaborador', 'new', 'intranet');
    end if;
  end if;

  return new;
exception when others then
  -- Erro aqui nunca bloqueia login.
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

revoke all on function public.handle_new_user() from public, anon, authenticated;

comment on function public.handle_new_user() is
  'Cria a linha de public.profiles do usuario novo, com username derivado da parte local do e-mail e tipo_conta decidido pelo dominio (equipe no dominio institucional, externo quando a entrada veio de convite, voluntario nos demais), e cria o vinculo em public.vinculos com estado new e origem intranet. So a Secretaria leva o vinculo de new a active, depois do termo assinado e da formacao verificada. Reescrita do handle_new_user do exemplo oficial da Supabase; o corpo inteiro fica em bloco de excecao porque falha aqui bloquearia o login.';


-- ============================================================
-- 17. Custom access token hook
--
-- Copia da migration 20240214114147_auth-hook.sql do exemplo oficial da
-- Supabase, com tres mudancas declaradas: claims proprias (papeis,
-- setor_principal, vinculo, papel_global e user_role), tolerancia lendo
-- workspace_members quando a pessoa ainda nao tem papel novo, e o corpo
-- inteiro dentro de um bloco de excecao.
--
-- O hook e um por projeto e altera o JWT de TODAS as sessoes, inclusive as da
-- Redacao. Por isso ele nasce tolerante: erro aqui nunca pode bloquear login.
-- Se algo falhar, devolve o evento intacto, a sessao sai sem claims e as
-- policies negam o que exige papel, o que e seguro.
-- ============================================================

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
set search_path = ''
as $$
declare
  v_user_id     uuid;
  v_claims      jsonb;
  v_papeis      jsonb;
  v_papel_global text;
  v_setor       uuid;
  v_vinculo     jsonb;
  v_role        text;
  v_coordenacao text;
begin
  v_user_id := (event ->> 'user_id')::uuid;
  v_claims  := coalesce(event -> 'claims', '{}'::jsonb);

  -- 1. Papeis vigentes, do maior alcance para o menor.
  select
    coalesce(jsonb_agg(jsonb_build_object('papel', up.papel, 'setor_id', up.setor_id)
                       order by p.alcance desc), '[]'::jsonb),
    (array_agg(up.papel order by p.alcance desc))[1]
  into v_papeis, v_papel_global
  from public.usuario_papeis up
  join public.papeis p on p.slug = up.papel and p.ativo
  where up.user_id = v_user_id
    and up.inicio <= now()
    and (up.fim is null or up.fim > now());

  -- 2. Setor principal do perfil.
  select pr.setor_principal_id into v_setor
    from public.profiles pr where pr.id = v_user_id;

  -- 3. Tolerancia: sem papel novo, o papel vem de workspace_members, que e o
  --    que a Redacao le hoje. Assim a Redacao continua funcionando antes de
  --    qualquer pessoa ganhar papel na intranet.
  if v_papel_global is null then
    select wm.role, wm.coordination into v_role, v_coordenacao
      from public.workspace_members wm
     where wm.user_id = v_user_id
     order by wm.created_at
     limit 1;

    v_papel_global := case v_role
      when 'admin'       then 'administrador'
      when 'editor'      then 'comunicacao'
      when 'colaborador' then 'colaborador'
      else null
    end;

    if v_papel_global is not null then
      if v_setor is null and v_coordenacao is not null then
        select s.id into v_setor
          from public.setores s
         where s.slug = v_coordenacao and s.ativo
         limit 1;
      end if;
      v_papeis := jsonb_build_array(
        jsonb_build_object('papel', v_papel_global, 'setor_id', v_setor)
      );
    end if;
  end if;

  -- 4. Vinculo vigente, preferindo o ativo.
  select jsonb_build_object('tipo', v.tipo, 'estado', v.estado)
    into v_vinculo
  from public.vinculos v
  where v.profile_id = v_user_id
    and (v.fim is null or v.fim > now())
  order by case v.estado when 'active' then 0 when 'new' then 1 else 2 end, v.inicio desc
  limit 1;

  v_claims := jsonb_set(v_claims, '{papeis}', coalesce(v_papeis, '[]'::jsonb));
  v_claims := jsonb_set(v_claims, '{setor_principal}', coalesce(to_jsonb(v_setor), 'null'::jsonb));
  v_claims := jsonb_set(v_claims, '{vinculo}', coalesce(v_vinculo, 'null'::jsonb));

  -- papel_global e a claim canonica do papel; user_role sai com o mesmo valor,
  -- como alias, para nao quebrar sessao em curso. Nenhuma policy depende de uma
  -- nem da outra: as duas servem so para a interface escolher o menu, porque
  -- public.autorizar() le apenas a claim papeis. user_role sai em migracao
  -- posterior marcada com o prefixo limpeza.
  v_claims := jsonb_set(v_claims, '{papel_global}', coalesce(to_jsonb(v_papel_global), 'null'::jsonb));
  v_claims := jsonb_set(v_claims, '{user_role}', coalesce(to_jsonb(v_papel_global), 'null'::jsonb));

  return jsonb_set(event, '{claims}', v_claims);
exception when others then
  -- Erro no hook nunca bloqueia login.
  return event;
end;
$$;
comment on function public.custom_access_token_hook(jsonb) is
  'Injeta no JWT as claims papeis, setor_principal, vinculo, papel_global e user_role. Copia da migration 20240214114147_auth-hook.sql do exemplo oficial slack-clone da Supabase, com claims proprias, tolerancia lendo workspace_members e bloco de excecao que devolve o evento intacto. E um por projeto e altera todas as sessoes, inclusive as da Redacao. papel_global e o nome novo do papel de maior alcance e user_role fica como alias do mesmo valor, para nao quebrar sessao em curso; user_role sai em migracao posterior marcada -- limpeza:. Nenhuma policy depende de papel_global nem de user_role: as duas servem para a interface escolher o menu. public.autorizar() le apenas a claim papeis.';


-- ============================================================
-- 17.1 Funcoes auxiliares que nascem com o diretorio
--
-- Ficam aqui, e nao no bloco 16, porque so existem para o que vem a seguir: as
-- duas de private sao lidas pela view do diretorio e pela policy de leitura de
-- profiles, e a de public e a unica porta de escrita de
-- profiles.mfa_verificado_em depois que a coluna saiu do grant de update.
-- Mesmo padrao das demais: security definer, stable quando so le, e
-- set search_path = '' porque search_path mutavel e vetor de sequestro de nome.
-- ============================================================

create or replace function private.alcance_do_diretorio()
returns text
language sql
security definer
stable
set search_path = ''
as $$
  select case
    when (select public.autorizar('pessoa.ver_restrito')) then 'completo'
    when exists (
      select 1 from public.vinculos v
      where v.profile_id = (select auth.uid())
        and v.estado = 'active'
        and (v.fim is null or v.fim > now())
        and v.tipo in ('colaborador','instrutor','diretoria')
    ) then 'completo'
    when exists (
      select 1 from public.vinculos v
      where v.profile_id = (select auth.uid())
        and v.estado = 'active'
        and (v.fim is null or v.fim > now())
        and v.tipo = 'voluntario'
    ) then 'setor'
    else 'minimo'
  end;
$$;

revoke all on function private.alcance_do_diretorio() from public, anon;
grant execute on function private.alcance_do_diretorio() to authenticated;

comment on function private.alcance_do_diretorio() is
  'Quanto do diretorio quem esta logado alcanca: completo para quem tem a permissao pessoa.ver_restrito e para vinculo ativo de tipo colaborador, instrutor ou diretoria; setor para vinculo ativo de tipo voluntario; minimo para vinculo em new ou inactive e para parceiro_externo. Responde pelo lado de quem consulta, que e o lado que a policy herdada da Redacao nao olha. E lida por public.profiles_diretorio.';

create or replace function private.compartilha_vinculo(p_profile_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.vinculos meu
    join public.vinculos outro on outro.workspace_id = meu.workspace_id
    where meu.profile_id = (select auth.uid())
      and meu.estado <> 'terminated'
      and (meu.fim is null or meu.fim > now())
      and outro.profile_id = p_profile_id
      and outro.estado <> 'terminated'
      and (outro.fim is null or outro.fim > now())
  );
$$;

revoke all on function private.compartilha_vinculo(uuid) from public, anon;
grant execute on function private.compartilha_vinculo(uuid) to authenticated;

comment on function private.compartilha_vinculo(uuid) is
  'Verdadeiro quando quem esta logado e a pessoa consultada tem, cada um, vinculo vigente no mesmo espaco, com estado diferente de terminated e fim nulo ou futuro. Sustenta a policy profiles_select_vinculo: pertencimento provado por vinculos, nunca por workspace_members, que barra todo voluntario.';

-- As duas funcoes abaixo existem porque public.profiles_diretorio e
-- security_invoker: o exists direto em public.usuario_papeis e o exists direto
-- em public.consentimentos eram avaliados com o RLS de quem consulta, e nenhuma
-- das duas policies abre a linha de outra pessoa. O resultado era diretorio
-- vazio no alcance minimo e telefone invisivel para a Secretaria. Cada uma
-- responde so o booleano da pergunta e nunca devolve a linha nem lista de dado
-- pessoal, que e o mesmo desenho de private.compartilha_vinculo acima.

create or replace function private.exerce_coordenacao_ou_secretaria(p_profile_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.usuario_papeis up
    where up.user_id = p_profile_id
      and up.papel in ('coordenador','secretaria')
      and up.inicio <= now()
      and (up.fim is null or up.fim > now())
  );
$$;

revoke all on function private.exerce_coordenacao_ou_secretaria(uuid) from public, anon;
grant execute on function private.exerce_coordenacao_ou_secretaria(uuid) to authenticated;

comment on function private.exerce_coordenacao_ou_secretaria(uuid) is
  'Verdadeiro quando a pessoa consultada tem concessao vigente do papel coordenador ou do papel secretaria. Existe porque o ramo de alcance minimo de public.profiles_diretorio consultava public.usuario_papeis direto e a view e security_invoker: a policy usuario_papeis_select_proprio so devolve a cada pessoa os papeis dela mesma, entao o exists dava falso e o recem-chegado, o voluntario inativo e o parceiro externo abriam /pessoas sem encontrar ninguem com quem falar, ao contrario do que a secao 5.2 promete. Devolve so o booleano da pergunta: nunca a linha de usuario_papeis, nunca a lista de papeis de terceiro. Defeito encontrado pela suite pgTAP do anexo 02b.';

create or replace function private.tem_consentimento_vigente(p_profile_id uuid, p_finalidade text)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.consentimentos c
    where c.profile_id = p_profile_id
      and c.finalidade = p_finalidade
      and c.revogado_em is null
  );
$$;

revoke all on function private.tem_consentimento_vigente(uuid, text) from public, anon;
grant execute on function private.tem_consentimento_vigente(uuid, text) to authenticated;

comment on function private.tem_consentimento_vigente(uuid, text) is
  'Verdadeiro quando existe consentimento daquela finalidade para aquela pessoa sem revogado_em, isto e, a linha que o indice unico parcial consentimentos_vigente_idx mantem unica. Existe porque public.profiles_diretorio checava o consentimento com um exists direto em public.consentimentos e a view e security_invoker: a policy consentimentos_select_titular so abre a linha para o titular e para quem tem lgpd.responder_titular ou trilha.ler_completa, permissoes que o seed da ao administrador e nao da a secretaria, entao o telefone aparecia para o administrador e sumia para a Secretaria, contra a secao 6.6, que nomeia secretaria e administrador como quem tem pessoa.ver_restrito. Nao afrouxa nada: devolve so um booleano, nunca a versao da politica, a evidencia ou a data, e as tres condicoes cumulativas de 6.6 continuam inteiras na view, inclusive a de pessoa.ver_restrito. Defeito encontrado pela suite pgTAP do anexo 02b.';

create or replace function public.registrar_verificacao_mfa()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if coalesce((select auth.jwt() ->> 'aal'), '') <> 'aal2' then
    raise exception 'Verificacao de segundo fator so e registrada em sessao aal2.'
      using errcode = '42501';
  end if;

  update public.profiles
     set mfa_verificado_em = now()
   where id = (select auth.uid());
end;
$$;

revoke all on function public.registrar_verificacao_mfa() from public, anon;
grant execute on function public.registrar_verificacao_mfa() to authenticated;

comment on function public.registrar_verificacao_mfa() is
  'Unica escrita de public.profiles.mfa_verificado_em, que saiu do grant de update de authenticated: grava now() so na linha de auth.uid() e so quando a claim aal do JWT corrente e aal2. A coluna e espelho de leitura; a idade da verificacao usada pelas RPCs de decisao e de assinatura e lida da claim amr do JWT.';


-- ============================================================
-- 18. Diretorio: view que aplica a regra de visibilidade
--
-- A policy profiles_select_shared da Redacao (20260820183812) libera todo
-- perfil para quem compartilha espaco, e migracao so acrescenta: ela nao e
-- removida aqui. A regra do diretorio (visibilidade escolhida pela pessoa,
-- setor de quem olha, desligado sumindo no mesmo instante) vive nesta view,
-- que e o que as telas /pessoas e /pessoas/[id] consultam. Substituir a
-- policy da Redacao por uma restritiva fica para uma migracao marcada
-- -- limpeza:, depois que a Redacao parar de depender dela.
-- ============================================================

create or replace view public.profiles_diretorio
with (security_invoker = true) as
select
  p.id,
  p.username,
  p.full_name,
  p.nome_social,
  coalesce(nullif(p.nome_social, ''), p.full_name) as nome_exibido,
  p.job_title,
  p.initials,
  p.color,
  p.avatar_path,
  p.tipo_conta,
  p.apresentacao,
  p.competencias,
  p.interesses,
  p.setor_principal_id,
  p.visibilidade_diretorio,
  case
    when p.id = (select auth.uid())
      or p.email_visivel
      or (select public.autorizar('pessoa.ver_restrito'))
    then p.email_contato
  end as email_contato,
  case
    when p.id = (select auth.uid())
      or (
        (select public.autorizar('pessoa.ver_restrito'))
        and p.telefone_visivel
        and (select private.tem_consentimento_vigente(p.id, 'telefone_no_diretorio'))
      )
    then p.telefone
  end as telefone
from public.profiles p
where p.eliminado_em is null
  and p.desativado_em is null
  and p.tipo_conta <> 'servico'
  and exists (
    select 1 from public.vinculos v
    where v.profile_id = p.id
      and v.estado = 'active'
      and (v.fim is null or v.fim > now())
  )
  and case (select private.alcance_do_diretorio())
    when 'completo' then (
      p.id = (select auth.uid())
      or (select public.autorizar('pessoa.ver_restrito'))
      or p.visibilidade_diretorio = 'todos'
      or (p.visibilidade_diretorio = 'setor' and (select private.mesmo_setor(p.id)))
    )
    when 'setor' then (
      p.id = (select auth.uid())
      or (select private.mesmo_setor(p.id))
    )
    else (
      p.id = (select auth.uid())
      or (select private.exerce_coordenacao_ou_secretaria(p.id))
      or exists (
        select 1
        from public.vinculos vv
        join public.setores s on s.id = vv.setor_id
        where vv.profile_id = p.id
          and vv.estado = 'active'
          and (vv.fim is null or vv.fim > now())
          and s.slug = 'voluntariado'
      )
    )
  end;

comment on view public.profiles_diretorio is
  'O diretorio de /pessoas. Aplica os dois lados da regra, e nao so o da pessoa olhada. Do lado de quem e olhado: ninguem aparece antes de vinculos.estado = active, desligado e eliminado somem no mesmo instante, e conta de tipo servico nunca aparece. Do lado de quem consulta, private.alcance_do_diretorio() decide: com completo valem as regras de visibilidade_diretorio, que prevalece sobre o papel de quem olha exceto para quem tem pessoa.ver_restrito; com setor so aparece quem private.mesmo_setor confirma; com minimo so aparecem coordenador e secretaria vigentes e quem tem vinculo no setor de slug voluntariado. Telefone sai para a propria pessoa e, fora dela, so para quem tem pessoa.ver_restrito, e ainda assim so com telefone_visivel e consentimento vigente de finalidade telefone_no_diretorio sem revogado_em; e-mail mantem a regra de email_visivel. security_invoker para que o RLS de quem consulta continue valendo. Nunca expoe public.profiles_restritos. As duas perguntas que a view faz sobre terceiro passaram a ser feitas por funcao security definer de private, e nao por exists direto na tabela: como a view e security_invoker, o exists em public.usuario_papeis e o exists em public.consentimentos eram avaliados com o RLS de quem consulta e davam falso, deixando o alcance minimo sem ninguem para falar e a Secretaria sem telefone. Agora sao private.exerce_coordenacao_ou_secretaria(uuid) e private.tem_consentimento_vigente(uuid, text), que devolvem so um booleano. Nenhuma condicao foi afrouxada: o telefone continua exigindo as tres condicoes cumulativas de 6.6. Defeito encontrado pela suite pgTAP do anexo 02b.';


-- ============================================================
-- 19. RLS ligado
-- ============================================================

alter table public.setores                 enable row level security;
alter table public.papeis                  enable row level security;
alter table public.papel_permissoes        enable row level security;
alter table public.profiles_restritos      enable row level security;
alter table public.vinculos                enable row level security;
alter table public.usuario_papeis          enable row level security;
alter table public.delegacoes              enable row level security;
alter table public.convites                enable row level security;
alter table public.formacoes               enable row level security;
alter table public.credenciais             enable row level security;
alter table public.termos_adesao           enable row level security;
alter table public.consentimentos          enable row level security;
alter table public.decisoes_institucionais enable row level security;
alter table public.politicas_assinatura    enable row level security;
alter table operacao.backups               enable row level security;
alter table operacao.fila_emails           enable row level security;
alter table operacao.orcamento_emails      enable row level security;
alter table operacao.uso_plano             enable row level security;
alter table operacao.limite_taxa           enable row level security;


-- ============================================================
-- 20. Policies
--
-- Nomeadas <tabela>_<operacao>_<intencao>, no molde de messages_select_member
-- da Redacao. Sempre to authenticated; anon nunca recebe policy. Nenhuma
-- consulta workspace_members, usuario_papeis ou vinculos direto.
-- ============================================================

-- ---------- setores ----------
drop policy if exists setores_select_membro on public.setores;
create policy setores_select_membro on public.setores for select to authenticated
  using ((select private.pertence_ao_espaco(workspace_id)));

drop policy if exists setores_insert_administrador on public.setores;
create policy setores_insert_administrador on public.setores for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('operacao.administrar'))
    and (select private.exige_aal2())
  );

drop policy if exists setores_update_administrador on public.setores;
create policy setores_update_administrador on public.setores for update to authenticated
  using ((select public.autorizar('operacao.administrar')))
  with check (
    (select public.autorizar('operacao.administrar'))
    and (select private.exige_aal2())
  );

-- ---------- papeis ----------
drop policy if exists papeis_select_autenticado on public.papeis;
create policy papeis_select_autenticado on public.papeis for select to authenticated
  using (true);

drop policy if exists papeis_insert_administrador on public.papeis;
create policy papeis_insert_administrador on public.papeis for insert to authenticated
  with check ((select public.autorizar('operacao.administrar')) and (select private.exige_aal2()));

drop policy if exists papeis_update_administrador on public.papeis;
create policy papeis_update_administrador on public.papeis for update to authenticated
  using ((select public.autorizar('operacao.administrar')))
  with check ((select public.autorizar('operacao.administrar')) and (select private.exige_aal2()));

-- ---------- papel_permissoes ----------
-- Leitura para qualquer pessoa autenticada, como no exemplo da Supabase: a
-- tela precisa explicar o que cada papel pode. Escrita so por migracao, para
-- que mudar a matriz de permissao seja ato versionado e revisado.
drop policy if exists papel_permissoes_select_autenticado on public.papel_permissoes;
create policy papel_permissoes_select_autenticado on public.papel_permissoes for select to authenticated
  using (true);

-- ---------- profiles (tabela da Redacao; so acrescenta policy) ----------
drop policy if exists profiles_select_vinculo on public.profiles;
create policy profiles_select_vinculo on public.profiles
  as permissive for select to authenticated
  using ((select private.compartilha_vinculo(id)));

comment on policy profiles_select_vinculo on public.profiles is
  'Acrescenta a profiles_select_shared da Redacao, que exige linha em workspace_members e por isso barra todo voluntario: aqui basta que quem consulta e a pessoa consultada tenham vinculo vigente no mesmo espaco. Existe porque a view public.profiles_diretorio e security_invoker e, sem esta policy, o diretorio nasce vazio para quem nao e da equipe editorial. profiles_select_shared nao e removida nem alterada: a substituicao fica para migracao posterior marcada -- limpeza:.';

drop policy if exists profiles_update_secretaria on public.profiles;
create policy profiles_update_secretaria on public.profiles for update to authenticated
  using ((select public.autorizar('pessoa.editar_restrito')))
  with check ((select public.autorizar('pessoa.editar_restrito')));

comment on policy profiles_update_secretaria on public.profiles is
  'Acrescenta a profiles_update_self da Redacao: Secretaria e administrador editam o perfil de terceiros (confirmar setor, desativar, registrar ultimo acesso). O trigger da Redacao continua impedindo troca de id e de e-mail.';

-- ---------- profiles_restritos ----------
drop policy if exists profiles_restritos_select_titular on public.profiles_restritos;
create policy profiles_restritos_select_titular on public.profiles_restritos for select to authenticated
  using (
    profile_id = (select auth.uid())
    or (select public.autorizar('pessoa.ver_restrito'))
  );

drop policy if exists profiles_restritos_insert_titular on public.profiles_restritos;
create policy profiles_restritos_insert_titular on public.profiles_restritos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (profile_id = (select auth.uid()) or (select public.autorizar('pessoa.editar_restrito')))
  );

drop policy if exists profiles_restritos_update_titular on public.profiles_restritos;
create policy profiles_restritos_update_titular on public.profiles_restritos for update to authenticated
  using (profile_id = (select auth.uid()) or (select public.autorizar('pessoa.editar_restrito')))
  with check (profile_id = (select auth.uid()) or (select public.autorizar('pessoa.editar_restrito')));

-- ---------- vinculos ----------
drop policy if exists vinculos_select_membro on public.vinculos;
create policy vinculos_select_membro on public.vinculos for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      profile_id = (select auth.uid())
      or estado = 'active'
      or (select public.autorizar('pessoa.confirmar_vinculo', setor_id))
      or (select public.autorizar('trilha.ler_completa'))
    )
  );

comment on policy vinculos_select_membro on public.vinculos is
  'Vinculo ativo e legivel por qualquer membro porque e o que o diretorio mostra. Vinculo em new, inactive, suspended ou terminated so aparece para a propria pessoa, para quem confirma vinculo naquele setor e para o auditor.';

drop policy if exists vinculos_insert_secretaria on public.vinculos;
create policy vinculos_insert_secretaria on public.vinculos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('pessoa.confirmar_vinculo', setor_id))
  );

drop policy if exists vinculos_update_secretaria on public.vinculos;
create policy vinculos_update_secretaria on public.vinculos for update to authenticated
  using ((select public.autorizar('pessoa.confirmar_vinculo', setor_id)))
  with check (
    (select public.autorizar('pessoa.confirmar_vinculo', setor_id))
    and (select private.exige_aal2())
  );

-- ---------- usuario_papeis ----------
drop policy if exists usuario_papeis_select_proprio on public.usuario_papeis;
create policy usuario_papeis_select_proprio on public.usuario_papeis for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select public.autorizar('papel.conceder', setor_id))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists usuario_papeis_insert_concessor on public.usuario_papeis;
create policy usuario_papeis_insert_concessor on public.usuario_papeis for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('papel.conceder', setor_id))
    and (select private.exige_aal2())
    and (papel not in ('administrador','auditor') or (select private.tem_papel('administrador')))
  );

comment on policy usuario_papeis_insert_concessor on public.usuario_papeis is
  'Conceder papel e decisao: exige aal2. Os papeis administrador e auditor so por quem ja e administrador, porque sao eles que enxergam a trilha e operam o banco.';

drop policy if exists usuario_papeis_update_concessor on public.usuario_papeis;
create policy usuario_papeis_update_concessor on public.usuario_papeis for update to authenticated
  using ((select public.autorizar('papel.revogar', setor_id)))
  with check (
    (select public.autorizar('papel.revogar', setor_id))
    and (select private.exige_aal2())
  );

drop policy if exists usuario_papeis_select_auth_admin on public.usuario_papeis;
create policy usuario_papeis_select_auth_admin on public.usuario_papeis
  as permissive for select to supabase_auth_admin using (true);

-- ---------- delegacoes ----------
drop policy if exists delegacoes_select_envolvido on public.delegacoes;
create policy delegacoes_select_envolvido on public.delegacoes for select to authenticated
  using (
    delegante_id = (select auth.uid())
    or delegado_id = (select auth.uid())
    or (select public.autorizar('papel.conceder', setor_id))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists delegacoes_insert_delegante on public.delegacoes;
create policy delegacoes_insert_delegante on public.delegacoes for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and criado_por = (select auth.uid())
    and (select public.autorizar('delegacao.criar', setor_id))
    and (select private.exige_aal2())
  );

drop policy if exists delegacoes_update_delegante on public.delegacoes;
create policy delegacoes_update_delegante on public.delegacoes for update to authenticated
  using (delegante_id = (select auth.uid()) or (select public.autorizar('papel.revogar', setor_id)))
  with check (delegante_id = (select auth.uid()) or (select public.autorizar('papel.revogar', setor_id)));

-- ---------- convites ----------
drop policy if exists convites_select_convidante on public.convites;
create policy convites_select_convidante on public.convites for select to authenticated
  using (
    criado_por = (select auth.uid())
    or (select public.autorizar('pessoa.convidar', setor_id))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists convites_insert_convidante on public.convites;
create policy convites_insert_convidante on public.convites for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and criado_por = (select auth.uid())
    and (select public.autorizar('pessoa.convidar', setor_id))
  );

drop policy if exists convites_update_convidante on public.convites;
create policy convites_update_convidante on public.convites for update to authenticated
  using (criado_por = (select auth.uid()) or (select public.autorizar('pessoa.convidar', setor_id)))
  with check (criado_por = (select auth.uid()) or (select public.autorizar('pessoa.convidar', setor_id)));

comment on policy convites_update_convidante on public.convites is
  'Serve a revogacao. O aceite nao passa por aqui: aceitarConvite e security definer, porque quem aceita ainda nao tem vinculo e portanto nao satisfaz policy nenhuma.';

-- ---------- formacoes ----------
drop policy if exists formacoes_select_titular on public.formacoes;
create policy formacoes_select_titular on public.formacoes for select to authenticated
  using (
    profile_id = (select auth.uid())
    or (select public.autorizar('pessoa.confirmar_vinculo'))
    or (select public.autorizar('pessoa.ver_restrito'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists formacoes_insert_titular on public.formacoes;
create policy formacoes_insert_titular on public.formacoes for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (profile_id = (select auth.uid()) and verificado_por is null)
      or (select public.autorizar('pessoa.confirmar_vinculo'))
    )
  );

drop policy if exists formacoes_update_verificador on public.formacoes;
create policy formacoes_update_verificador on public.formacoes for update to authenticated
  using (
    (profile_id = (select auth.uid()) and verificado_em is null)
    or (select public.autorizar('pessoa.confirmar_vinculo'))
  )
  with check (
    (profile_id = (select auth.uid()) and verificado_em is null)
    or ((select public.autorizar('pessoa.confirmar_vinculo')) and (select private.exige_aal2()))
  );

-- Um dos quatro unicos delete para authenticated em toda a intranet.
drop policy if exists formacoes_delete_titular on public.formacoes;
create policy formacoes_delete_titular on public.formacoes for delete to authenticated
  using (profile_id = (select auth.uid()) and verificado_em is null);

comment on policy formacoes_delete_titular on public.formacoes is
  'A pessoa apaga a propria formacao enquanto ninguem a verificou: ate ali e rascunho de cadastro, nao registro institucional. Um dos quatro unicos delete para authenticated, ao lado de grupo_membros, comentarios e pastas.';

-- ---------- credenciais ----------
drop policy if exists credenciais_select_titular on public.credenciais;
create policy credenciais_select_titular on public.credenciais for select to authenticated
  using (
    profile_id = (select auth.uid())
    or (select public.autorizar('pessoa.ver_restrito'))
    or (select public.autorizar('pessoa.confirmar_vinculo'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists credenciais_insert_titular on public.credenciais;
create policy credenciais_insert_titular on public.credenciais for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (profile_id = (select auth.uid()) and tipo = 'registro_profissional' and status = 'valid')
      or (select public.autorizar('pessoa.editar_restrito'))
    )
  );

drop policy if exists credenciais_update_secretaria on public.credenciais;
create policy credenciais_update_secretaria on public.credenciais for update to authenticated
  using ((select public.autorizar('pessoa.editar_restrito')))
  with check ((select public.autorizar('pessoa.editar_restrito')) and (select private.exige_aal2()));

-- ---------- termos_adesao ----------
drop policy if exists termos_adesao_select_titular on public.termos_adesao;
create policy termos_adesao_select_titular on public.termos_adesao for select to authenticated
  using (
    profile_id = (select auth.uid())
    or (select public.autorizar('pessoa.ver_restrito'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists termos_adesao_insert_titular on public.termos_adesao;
create policy termos_adesao_insert_titular on public.termos_adesao for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (profile_id = (select auth.uid()) or (select public.autorizar('pessoa.editar_restrito')))
  );

drop policy if exists termos_adesao_update_secretaria on public.termos_adesao;
create policy termos_adesao_update_secretaria on public.termos_adesao for update to authenticated
  using ((select public.autorizar('pessoa.editar_restrito')))
  with check ((select public.autorizar('pessoa.editar_restrito')) and (select private.exige_aal2()));

comment on policy termos_adesao_update_secretaria on public.termos_adesao is
  'A assinatura em si nao passa por aqui: quem grava assinado_em e hash_pdf e a RPC de assinatura da parte 4, que confere aal2 e o hash da versao.';

-- ---------- consentimentos ----------
drop policy if exists consentimentos_select_titular on public.consentimentos;
create policy consentimentos_select_titular on public.consentimentos for select to authenticated
  using (
    profile_id = (select auth.uid())
    or (select public.autorizar('lgpd.responder_titular'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists consentimentos_insert_titular on public.consentimentos;
create policy consentimentos_insert_titular on public.consentimentos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and profile_id = (select auth.uid())
    and origem = 'intranet'
    and registrado_por is null
  );

comment on policy consentimentos_insert_titular on public.consentimentos is
  'Consentimento e ato pessoal: pela intranet so o proprio titular insere, e sem registrador. Nem Secretaria nem administrador consentem por outra pessoa (LGPD art. 8).';

drop policy if exists consentimentos_insert_registrador on public.consentimentos;
create policy consentimentos_insert_registrador on public.consentimentos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('pessoa.editar_restrito'))
    and origem in ('papel','presencial')
    and profile_id <> (select auth.uid())
    and registrado_por = (select auth.uid())
    and comprovante_documento_id is not null
    and (select private.exige_aal2())
  );

comment on policy consentimentos_insert_registrador on public.consentimentos is
  'A outra porta, e a unica: consentimento colhido fora da intranet, no papel ou presencialmente, so vale registrado com o comprovante digitalizado na biblioteca, por quem tem pessoa.editar_restrito, com aal2 e com registrado_por nomeando quem registrou. Nao e consentir por outra pessoa, e transcrever o ato dela com prova. Sem esta porta a ficha de saude continuaria em papel.';

drop policy if exists consentimentos_update_titular on public.consentimentos;
create policy consentimentos_update_titular on public.consentimentos for update to authenticated
  using (profile_id = (select auth.uid()) or (select public.autorizar('lgpd.responder_titular')))
  with check (profile_id = (select auth.uid()) or (select public.autorizar('lgpd.responder_titular')));

-- ---------- decisoes_institucionais ----------
drop policy if exists decisoes_institucionais_select_membro on public.decisoes_institucionais;
create policy decisoes_institucionais_select_membro on public.decisoes_institucionais for select to authenticated
  using ((select private.pertence_ao_espaco(workspace_id)));

drop policy if exists decisoes_institucionais_insert_administrador on public.decisoes_institucionais;
create policy decisoes_institucionais_insert_administrador on public.decisoes_institucionais for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('operacao.administrar'))
    and (select private.exige_aal2())
  );

drop policy if exists decisoes_institucionais_update_administrador on public.decisoes_institucionais;
create policy decisoes_institucionais_update_administrador on public.decisoes_institucionais for update to authenticated
  using ((select public.autorizar('operacao.administrar')))
  with check ((select public.autorizar('operacao.administrar')) and (select private.exige_aal2()));

-- ---------- politicas_assinatura ----------
drop policy if exists politicas_assinatura_select_membro on public.politicas_assinatura;
create policy politicas_assinatura_select_membro on public.politicas_assinatura for select to authenticated
  using ((select private.pertence_ao_espaco(workspace_id)));

drop policy if exists politicas_assinatura_insert_administrador on public.politicas_assinatura;
create policy politicas_assinatura_insert_administrador on public.politicas_assinatura for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('operacao.administrar'))
    and (select private.exige_aal2())
  );

-- ---------- operacao ----------
drop policy if exists backups_select_administrador on operacao.backups;
create policy backups_select_administrador on operacao.backups for select to authenticated
  using (
    (select public.autorizar('operacao.administrar'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists fila_emails_select_destinatario on operacao.fila_emails;
create policy fila_emails_select_destinatario on operacao.fila_emails for select to authenticated
  using (
    destinatario_id = (select auth.uid())
    or (select public.autorizar('operacao.administrar'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists orcamento_emails_select_administrador on operacao.orcamento_emails;
create policy orcamento_emails_select_administrador on operacao.orcamento_emails for select to authenticated
  using (
    (select public.autorizar('operacao.administrar'))
    or (select public.autorizar('trilha.ler_completa'))
  );

drop policy if exists uso_plano_select_administrador on operacao.uso_plano;
create policy uso_plano_select_administrador on operacao.uso_plano for select to authenticated
  using (
    (select public.autorizar('operacao.administrar'))
    or (select public.autorizar('trilha.ler_completa'))
  );

comment on policy uso_plano_select_administrador on operacao.uso_plano is
  'So leitura, e so para administrador e auditor. Nao ha policy de insert nem de update para authenticated em operacao: quem escreve e o job de cron pela chave de servico ou uma funcao security definer.';


-- ============================================================
-- 21. GRANTs explicitos
--
-- A intranet nao repete o "grant select, insert, update, delete on all tables
-- in schema public to authenticated" da Redacao. Aqui o padrao e: revogar de
-- public e de anon, e conceder por tabela apenas as operacoes que tem policy.
-- Isso importa porque o Supabase concede privilegio a anon por default
-- privileges em public: sem o revoke abaixo, cada tabela nova nasceria
-- alcancavel por anon. Padrao do hardening inicial do Makerkit Lite (MIT).
-- ============================================================

grant usage on schema public   to authenticated;
grant usage on schema private  to authenticated;
grant usage on schema operacao to authenticated;

-- A chave de servico renderiza as rotas publicas no servidor e precisa alcancar
-- operacao.permitir. Sem o usage no schema a role chamadora nao resolvia a
-- funcao e o limite de taxa das rotas publicas simplesmente nao existia.
grant usage on schema operacao to service_role;

-- ---------- funcoes ----------
revoke all on function private.exige_aal2()                 from public, anon;
revoke all on function private.vinculo_ativo()              from public, anon;
revoke all on function private.setor_do_usuario()           from public, anon;
revoke all on function private.mesmo_setor(uuid)            from public, anon;
revoke all on function private.papel_global()               from public, anon;
revoke all on function private.tem_papel(text, uuid)        from public, anon;
revoke all on function public.autorizar(public.permissao, uuid) from public, anon;
revoke all on function public.tocar_atualizado_em()         from public, anon;
revoke all on function public.lista_para_texto(text[])      from public;
revoke all on function public.validar_escopo_do_papel()     from public, anon;
revoke all on function public.exigir_consentimento_saude()  from public, anon;
revoke all on function public.congelar_consentimento()      from public, anon;
revoke all on function public.normalizar_email_convite()    from public, anon;
revoke all on function public.consultar_convite(text)       from public, anon;
revoke all on function operacao.permitir(text, integer, interval) from public, anon;

grant execute on function private.exige_aal2()          to authenticated;
grant execute on function private.vinculo_ativo()       to authenticated;
grant execute on function private.setor_do_usuario()    to authenticated;
grant execute on function private.mesmo_setor(uuid)     to authenticated;
grant execute on function private.papel_global()        to authenticated;
grant execute on function private.tem_papel(text, uuid) to authenticated;
grant execute on function public.autorizar(public.permissao, uuid) to authenticated;
grant execute on function public.lista_para_texto(text[]) to authenticated;

-- As duas funcoes da pagina publica. anon nao executa nenhuma das duas: as
-- rotas publicas passam a ser renderizadas no servidor com a chave de servico,
-- como ja acontece em public.verificar_codigo, de modo que anon nao fique com
-- privilegio nenhum em funcao, tabela ou view, que e o que o teste de grants
-- reprova. Retorno fixo, sem dado pessoal em claro, sob limite de taxa.
grant execute on function public.consultar_convite(text) to authenticated, service_role;
grant execute on function operacao.permitir(text, integer, interval) to authenticated, service_role;

-- ---------- tabelas de public ----------
revoke all on table public.setores from public, anon;
grant select, insert, update on table public.setores to authenticated;

revoke all on table public.papeis from public, anon;
grant select, insert, update on table public.papeis to authenticated;

revoke all on table public.papel_permissoes from public, anon;
grant select on table public.papel_permissoes to authenticated;

revoke all on table public.profiles_restritos from public, anon;
grant select, insert, update on table public.profiles_restritos to authenticated;

revoke all on table public.vinculos from public, anon;
grant select, insert, update on table public.vinculos to authenticated;

revoke all on table public.usuario_papeis from public, anon;
grant select, insert, update on table public.usuario_papeis to authenticated;

revoke all on table public.delegacoes from public, anon;
grant select, insert, update on table public.delegacoes to authenticated;

revoke all on table public.convites from public, anon;
grant select, insert, update on table public.convites to authenticated;

revoke all on table public.formacoes from public, anon;
grant select, insert, update, delete on table public.formacoes to authenticated;

revoke all on table public.credenciais from public, anon;
grant select, insert, update on table public.credenciais to authenticated;

revoke all on table public.termos_adesao from public, anon;
grant select, insert, update on table public.termos_adesao to authenticated;

revoke all on table public.consentimentos from public, anon;
grant select, insert, update on table public.consentimentos to authenticated;

revoke all on table public.decisoes_institucionais from public, anon;
grant select, insert, update on table public.decisoes_institucionais to authenticated;

revoke all on table public.politicas_assinatura from public, anon;
grant select, insert on table public.politicas_assinatura to authenticated;

revoke all on public.profiles_diretorio from public, anon;
grant select on public.profiles_diretorio to authenticated;

-- Tabela da Redacao: as colunas de seguranca saem do alcance da
-- profiles_update_self, que a Redacao criou e que nao restringe coluna. Como
-- grant de update na tabela inteira vale para toda coluna, revogar coluna a
-- coluna nao teria efeito: o privilegio de tabela e revogado e reconcedido pela
-- lista das colunas restantes, sem as seis que decidem acesso. Quem grava
-- mfa_verificado_em passa a ser public.registrar_verificacao_mfa(); as outras
-- cinco so pela policy profiles_update_secretaria.
do $$
declare
  v_colunas text;
begin
  select string_agg(quote_ident(column_name), ', ' order by ordinal_position)
    into v_colunas
    from information_schema.columns
   where table_schema = 'public'
     and table_name   = 'profiles'
     and is_generated = 'NEVER'
     and column_name not in (
       'mfa_verificado_em', 'tipo_conta', 'setor_principal_id',
       'acesso_expira_em', 'desativado_em', 'eliminado_em'
     );

  execute 'revoke update on table public.profiles from authenticated';
  execute format('grant update (%s) on table public.profiles to authenticated', v_colunas);
end $$;

-- limpeza: o delete de authenticated em public.profiles, que policy nenhuma
-- sustenta, nao e revogado aqui. E mudanca subtrativa em tabela de producao da
-- Redacao, e migracao da intranet so acrescenta: a revogacao vai em
-- supabase/migrations/20260901000000_limpeza_delete_profiles.sql, aplicada
-- depois do deploy que parou de depender do privilegio e acompanhada do teste
-- que prova a ausencia de uso. Ate la o RLS ja recusa o delete, e o teste
-- supabase/tests/grants_test.sql segue apontando o privilegio sem policy.

-- ---------- tabelas de operacao ----------
revoke all on table operacao.backups          from public, anon;
revoke all on table operacao.fila_emails      from public, anon;
revoke all on table operacao.orcamento_emails from public, anon;
revoke all on table operacao.uso_plano        from public, anon;
revoke all on table operacao.limite_taxa      from public, anon, authenticated;

grant select on table operacao.backups          to authenticated;
grant select on table operacao.fila_emails      to authenticated;
grant select on table operacao.orcamento_emails to authenticated;
grant select on table operacao.uso_plano        to authenticated;

-- ---------- supabase_auth_admin: o que o hook de token precisa ler ----------
-- Padrao do arquivo de origem (20240214114147_auth-hook.sql do exemplo da
-- Supabase): a role do Auth nao e superusuaria e nao ignora RLS, entao precisa
-- de grant e de policy propria em cada tabela que o hook consulta.
grant usage on schema public to supabase_auth_admin;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook(jsonb) from public, authenticated, anon;

grant select on table public.papeis            to supabase_auth_admin;
grant select on table public.usuario_papeis    to supabase_auth_admin;
grant select on table public.papel_permissoes  to supabase_auth_admin;
grant select on table public.setores           to supabase_auth_admin;
grant select on table public.vinculos          to supabase_auth_admin;
grant select on table public.workspace_members to supabase_auth_admin;

-- Duas colunas, e so estas duas: o hook precisa do setor principal para a
-- claim, e grant por coluna evita abrir o perfil inteiro para a role do Auth.
grant select (id, setor_principal_id) on table public.profiles to supabase_auth_admin;

drop policy if exists papeis_select_auth_admin on public.papeis;
create policy papeis_select_auth_admin on public.papeis
  as permissive for select to supabase_auth_admin using (true);

drop policy if exists papel_permissoes_select_auth_admin on public.papel_permissoes;
create policy papel_permissoes_select_auth_admin on public.papel_permissoes
  as permissive for select to supabase_auth_admin using (true);

drop policy if exists setores_select_auth_admin on public.setores;
create policy setores_select_auth_admin on public.setores
  as permissive for select to supabase_auth_admin using (true);

drop policy if exists vinculos_select_auth_admin on public.vinculos;
create policy vinculos_select_auth_admin on public.vinculos
  as permissive for select to supabase_auth_admin using (true);

drop policy if exists workspace_members_select_auth_admin on public.workspace_members;
create policy workspace_members_select_auth_admin on public.workspace_members
  as permissive for select to supabase_auth_admin using (true);

drop policy if exists profiles_select_auth_admin on public.profiles;
create policy profiles_select_auth_admin on public.profiles
  as permissive for select to supabase_auth_admin using (true);

comment on policy profiles_select_auth_admin on public.profiles is
  'Existe so para o hook de token ler setor_principal_id. O grant e por coluna (id e setor_principal_id), entao a policy nao abre o perfil inteiro para a role do Auth.';


-- ============================================================
-- 22. Seed: setores, papeis, matriz de permissoes, decisoes D01 a D47 e
--     politicas de assinatura
--
-- Idempotente: on conflict do nothing. Nomes das coordenacoes vindos do mapa
-- do ecossistema, secao 1. Nenhum dado pessoal entra em seed.
-- ============================================================

insert into public.setores (workspace_id, slug, nome, tipo, restrito_por_padrao)
select w.id, s.slug, s.nome, 'coordenacao', s.restrito
from public.workspaces w
cross join (values
  ('comunicacao',        'Comunicação',        false),
  ('humanitario',        'Humanitário',        false),
  ('grd',                'GRD',                false),
  ('saude',              'Saúde',              true),
  ('voluntariado',       'Voluntariado',       false),
  ('primeiros-socorros', 'Primeiros Socorros', false),
  ('diretoria',          'Diretoria',          false)
) as s(slug, nome, restrito)
where w.kind = 'production'
on conflict do nothing;

insert into public.papeis (slug, nome, descricao, escopo, exige_mfa, somente_leitura, alcance) values
  ('administrador',    'Administrador',    'Opera a instalação: papéis, setores, hook, MFA de terceiros e lixeira. No máximo duas pessoas.', 'global', true,  false, 100),
  ('diretoria',        'Diretoria',        'Homologa após o coordenador, assina e publica avisos oficiais.',                                   'global', true,  false,  90),
  ('secretaria',       'Secretaria',       'Convida, confirma vínculo, edita dado restrito e recebe termos assinados.',                        'global', true,  false,  80),
  ('comunicacao',      'Comunicação',      'Equipe editorial herdada do papel editor da Redação; aprova uso de imagem.',                       'global', false, false,  70),
  ('coordenador',      'Coordenador',      'Dono do mural e das pastas do setor; aprova na primeira linha o que é do setor.',                  'setor',  false, false,  60),
  ('instrutor',        'Instrutor',        'Publica no mural do setor de formação e verifica a formação de quem instruiu.',                    'setor',  false, false,  50),
  ('encarregado',      'Encarregado',      'Encarregado de dados do art. 41 da LGPD: responde ao titular e decide a eliminação.',              'global', true,  false,  45),
  ('auditor',          'Auditor',          'Leitura da trilha completa. Nunca escreve.',                                                       'global', true,  true,   40),
  ('colaborador',      'Colaborador',      'Equipe com conta no domínio institucional.',                                                       'global', false, false,  30),
  ('voluntario',       'Voluntário',       'Voluntário com vínculo ativo.',                                                                    'global', false, false,  20),
  ('parceiro_externo', 'Parceiro externo', 'Convidado com prazo; responde a pedidos dirigidos a ele.',                                          'global', false, false,  10)
on conflict (slug) do nothing;

insert into public.papel_permissoes (papel, permissao)
select v.papel, v.permissao::public.permissao
from (values
  ('voluntario','documento.enviar'), ('voluntario','autorizacao.abrir'),

  ('colaborador','documento.enviar'), ('colaborador','documento.versionar'),
  ('colaborador','mural.publicar'),   ('colaborador','autorizacao.abrir'),

  ('instrutor','documento.enviar'),   ('instrutor','documento.versionar'),
  ('instrutor','mural.publicar'),     ('instrutor','autorizacao.abrir'),
  ('instrutor','pessoa.confirmar_vinculo'), ('instrutor','autorizacao.aprovar'),

  ('coordenador','pessoa.convidar'),  ('coordenador','pessoa.confirmar_vinculo'),
  ('coordenador','grupo.criar'),      ('coordenador','grupo.administrar'),
  ('coordenador','mural.publicar'),   ('coordenador','mural.aprovar'),
  ('coordenador','mural.moderar'),    ('coordenador','mural.ver_relatorio'),
  ('coordenador','documento.enviar'), ('coordenador','documento.versionar'),
  ('coordenador','documento.mover'),  ('coordenador','documento.classificar'),
  ('coordenador','documento.permissionar'),
  ('coordenador','autorizacao.abrir'),('coordenador','autorizacao.aprovar'),
  ('coordenador','delegacao.criar'),

  ('comunicacao','mural.publicar'),   ('comunicacao','mural.aprovar'),
  ('comunicacao','mural.moderar'),    ('comunicacao','mural.ver_relatorio'),
  ('comunicacao','documento.enviar'), ('comunicacao','documento.versionar'),
  ('comunicacao','documento.classificar'),
  ('comunicacao','autorizacao.abrir'),('comunicacao','autorizacao.aprovar'),

  ('diretoria','mural.publicar'),     ('diretoria','mural.aprovar'),
  ('diretoria','mural.ver_relatorio'),('diretoria','documento.enviar'),
  ('diretoria','documento.versionar'),('diretoria','documento.classificar'),
  ('diretoria','autorizacao.abrir'),  ('diretoria','autorizacao.aprovar'),
  ('diretoria','autorizacao.homologar'), ('diretoria','autorizacao.assinar'),
  ('diretoria','delegacao.criar'),

  ('secretaria','pessoa.convidar'),   ('secretaria','pessoa.confirmar_vinculo'),
  ('secretaria','pessoa.ver_restrito'),('secretaria','pessoa.editar_restrito'),
  ('secretaria','papel.conceder'),    ('secretaria','papel.revogar'),
  ('secretaria','mural.publicar'),    ('secretaria','documento.enviar'),
  ('secretaria','documento.versionar'),('secretaria','documento.mover'),
  ('secretaria','documento.classificar'),
  ('secretaria','autorizacao.abrir'), ('secretaria','autorizacao.aprovar'),
  ('secretaria','autorizacao.assinar'),('secretaria','assinatura.conferir'),

  ('auditor','trilha.ler_completa'),

  ('encarregado','lgpd.responder_titular'), ('encarregado','trilha.ler_completa'),

  ('parceiro_externo','autorizacao.assinar')
) as v(papel, permissao)
on conflict (papel, permissao) do nothing;

-- Administrador recebe todas as permissões do enum, inclusive as que forem
-- acrescentadas por alter type em migração futura (o insert é reexecutável).
insert into public.papel_permissoes (papel, permissao)
select 'administrador', p
from unnest(enum_range(null::public.permissao)) as p
on conflict (papel, permissao) do nothing;

-- As 47 decisoes da recomendacao, e nao apenas as doze da fase 0: decisao que
-- fica so em paragrafo e decisao que a opcao padrao toma sozinha e publica como
-- fato consumado. Todas nascem pending, com opcao_recomendada copiada palavra
-- por palavra do corpo do escopo e revisao_em preenchida, que e o que faz a
-- revisao aparecer como tarefa em /configuracoes/decisoes e nao como
-- esquecimento. O check do codigo ja aceita ate D99.
insert into public.decisoes_institucionais (workspace_id, codigo, titulo, opcao_recomendada, status, revisao_em)
select w.id, d.codigo, d.titulo, d.recomendada, 'pending', (current_date + interval '12 months')::date
from public.workspaces w
cross join (values
  ('D01','Custo mensal e planos (Vercel Pro, Supabase Pro, Resend, Workspace)',
        'Aprovar dois tetos, e não um: US$ 55 a 75 por mês em regime normal, com um assento pago na Vercel, e até US$ 105 nos meses de transição, em que convivem dois projetos Supabase e o segundo assento de emergência. Time da Vercel em nome da filial, Diretoria como owner e prestador como membro; patrocínio pedido à Vercel em paralelo.'),
  ('D02','Região de hospedagem e transferência internacional',
        'Projeto novo em sa-east-1 no plano Pro.'),
  ('D03','Regra de vínculo e tipos de conta',
        'equipe por Google no domínio, voluntario por código de seis dígitos, externo por convite com prazo.'),
  ('D04','Política de assinatura por tipo de ato',
        'Em politicas_assinatura: simples para avisos oficiais, autorizações leves, homologações internas e termo de adesão; avancada no gov.br para termos com parceiros, ofícios externos, atas da Junta e prestação de contas; qualificada só para cartório ou órgão público. O termo de adesão fica em simples.'),
  ('D05','Enquadramento LGPD e encarregado',
        'Registrar por escrito o juízo sobre larga escala e nomear encarregado, com canal do titular em /privacidade.'),
  ('D06','Relação com o Registro Único Nacional de Voluntários',
        'Cadastro próprio (Estatuto art. 67, parágrafo 2), guardando só registro_nacional_id e civicrm_contact_id, sem envio automático.'),
  ('D07','Intranet como provedor de identidade da Redação e do Curso',
        'Sim para a Redação nesta rodada, pelo roteiro ordenado; Secretaria do Curso depois; aluno nunca ganha conta.'),
  ('D08','Diretriz de uso do emblema e do nome em sistemas digitais',
        'Pedir a diretriz ao Órgão Central por ofício agora e, até a resposta, usar só o nome por extenso.'),
  ('D09','Guarda e rotação do certificado e da chave da filial',
        'Chave só em segredo da Vercel, cópia lacrada com a Diretoria, rotação anual registrada, prestador como operador.'),
  ('D10','Qual projeto Supabase',
        'Projeto novo em sa-east-1 no Pro, com a Redação migrando para dentro e o projeto antigo pausado depois.'),
  ('D11','Resultado do piloto: o que fica no Google Workspace',
        'Aplicar os limiares da tabela de métricas; diretório único, mural com confirmação de leitura, trâmite e assinatura são sempre código próprio.'),
  ('D12','Onde a biblioteca guarda os documentos',
        'Drive se o piloto passar e o desenho técnico de gdrive da seção 3 for aprovado junto; senão Vercel Blob privado; Storage no Pro como terceira.'),
  ('D13','Coordenações e pessoas do piloto',
        'Voluntariado e GRD, com seis pessoas por teste, entre elas três voluntários sem conta Google e um observador (3).'),
  ('D14','Formações que condicionam o vínculo a active e data de corte',
        'CBFI e primeiros socorros presencial, validados por instrutor ou por Voluntariado, exigidos só a partir da data de corte registrada na própria decisão; vínculo herdado pela carga inicial não é rebaixado (6.1, 13).'),
  ('D15','Secretaria é setor ou papel global',
        'Papel global ligado à Diretoria, sem mural próprio (5.2).'),
  ('D16','Retenção por grupo de campos do perfil',
        'Adotar a tabela de 6.5 como padrão provisório, com parecer antes da fase 4 (6.5).'),
  ('D17','Membros Juvenis nesta rodada',
        'Não; responsavel_profile_id fica previsto e a recusa de menor de 18 é trigger no banco, não regra de tela, porque é a evidência que sustenta o enquadramento de D05 (6.5).'),
  ('D18','Dois administradores e donos das contas',
        'Uma pessoa da Diretoria como dona das contas e do papel, com o prestador como segundo, e o teto de dois conferido por trigger em usuario_papeis (5.3).'),
  ('D19','Dono de cada mural e da Comunidade',
        'Coordenador por setor; Comunicação no geral e no grupo de avisos; dois administradores nomeados (8.3, 8.4).'),
  ('D20','Limiares de adoção para a fase 6',
        '50 por cento de leitura e 70 por cento de confirmação constroem; abaixo de 25 por cento em 60 dias, para; e se o abandono no login passar de 40 por cento, os limiares não se aplicam e a decisão é adiada até o funil de entrada ser corrigido (8.5).'),
  ('D21','Mural da Diretoria',
        'Só a Diretoria publica, com aprovação prévia, comentários desligados e visibilidade membros (8.3).'),
  ('D22','Reserva diária de e-mails e Resend Pro',
        '40 para autenticação, 50 para a fila, 10 de folga; Pro com três dias em sete acima de 80 e-mails ou qualquer código de login recusado por cota, e obrigatoriamente na entrada da fase 2 se N mais M passar de quarenta pessoas (12.4).'),
  ('D23','Telefone e e-mail no diretório',
        'Telefone nunca na lista nem na busca; no cartão só para quem tem pessoa.ver_restrito, com telefone_visivel marcado pela pessoa e consentimento vigente de finalidade telefone_no_diretorio; e-mail com email_visivel (6.6).'),
  ('D24','Edição de aviso obrigatório publicado',
        'Sim: incrementa versao e gera nova pendência (8.3).'),
  ('D25','Coordenador cria grupo de projeto',
        'Sim, do próprio setor e com data de fim; o admin é notificado e pode arquivar (7.2).'),
  ('D26','API do WhatsApp Business',
        'Só se a métrica justificar e a Diretoria aprovar custo por conversa orçado (8.4).'),
  ('D27','Prazos de guarda que a norma não fixa',
        'Termos pelo prazo prescricional do desligamento, contado do fim do vínculo; ofício e relatório por cinco anos; imagem enquanto vigorar; certificado enquanto puder ser validado. Tipo com prazo ainda pendente não bloqueia direito do titular, bloqueia apenas a eliminação automática; D27 fecha antes do fim da fase 3 e o CI reprova o deploy da fase 4 com tipo ainda pendente (9.5).'),
  ('D28','Revisor jurídico dos modelos',
        'A Diretoria nomeia pessoa ou escritório e fixa prazo antes de a fase 3 terminar (9.5).'),
  ('D29','Publicar documento publico fora da intranet',
        'Não nesta rodada; publicação externa continua pela Redação e pelo site (9.3).'),
  ('D30','Extração de texto ou OCR',
        'Só PDF com camada de texto e DOCX, com teto de 25 MB e 300 páginas, em rota Node com biblioteca nomeada no ARQUITETURA.md e job de reprocessamento; OCR na fase 2 (9.4).'),
  ('D31','Materializar permissões da biblioteca',
        'Começar com private.papel_na_pasta e materializar só acima de 300 ms com volume real (9.3).'),
  ('D32','Tipos leves com aprovação por decurso de prazo',
        'Só acesso a pasta e participação em ação, com 5 dias úteis; ressarcimento nunca aprova por decurso, porque a Lei 9.608 exige autorização expressa anterior à despesa (10.2).'),
  ('D33','Quem homologa pela Diretoria e com que quórum',
        'Qualquer membro com papel diretoria, quórum 1, com todos notificados (10.2).'),
  ('D34','Quem registra o resultado do validador do ITI',
        'Conferente distinto do signatário, entre quem exerce autorizacao.homologar, que hoje são diretoria e administrador; se a Diretoria quiser a Secretaria conferindo, a permissão de conferência entra como valor novo do enum permissao em migração própria, porque a policy é escrita sobre permissão e não sobre papel (10.4).'),
  ('D35','Prazos das etapas e cadência de lembrete',
        '5, 5 e 10 dias úteis; lembrete na véspera e no dia; escalonamento um dia útil depois (10.3).'),
  ('D36','Delegado de outro setor ou papel',
        'Só mesmo papel no mesmo setor, ou membro da Diretoria, com evento na linha do tempo (10.3).'),
  ('D37','revogada na página pública',
        'Sim, só no fluxo de imagem, sem nome, setor ou data além do dia, e com o campo de estado sempre presente na resposta para que a ausência de valor não denuncie o fluxo (10.6).'),
  ('D38','Quem exerce o papel auditor',
        'Um membro do órgão de revisão de contas ou do conselho, mais o admin técnico, ambos só leitura (5.2).'),
  ('D39','Lembretes por rota da Vercel ou pg_net',
        'Rota chamada pelo cron da Vercel, com pg_cron só mudando estados (10.3).'),
  ('D40','Retenção e base legal por fluxo da trilha',
        'Adotar a proposta da pesquisa de rastreabilidade, revista com o encarregado (12.5).'),
  ('D41','Destino do backup diário',
        'Bucket S3 dedicado em nome da filial, cotado antes da fase 0; Drive só depois de liberar espaço (12.2).'),
  ('D42','Destino do projeto de ca-central-1',
        'Reaproveitar como homologação com seed sintético, apagando todo dado real antes (6.4).'),
  ('D43','Migrações pelo CI ou à mão',
        'Automático no merge, com o job bloqueando o deploy quando falhar, e migração removedora só com o prefixo limpeza (12.1).'),
  ('D44','Canal do titular',
        'Formulário mais caixa privacidade@ à Diretoria, com pessoa nomeada para responder em 15 dias (12.5).'),
  ('D45','Senha e sessão',
        '12 caracteres com três classes, sessão de 30 dias, sem sessão única; expiração por inatividade de 7 dias só para papéis com exige_mfa (12.3).'),
  ('D46','gitleaks e pnpm audit bloqueadores',
        'Sim, desde o primeiro commit (12.3).'),
  ('D47','Gatilhos numéricos da fase 2 e da API de assinatura',
        'Manter cinco arquivos por mês e 20 documentos por mês por seis meses, revisando com operacao.uso_plano (12.5).')
) as d(codigo, titulo, recomendada)
where w.kind = 'production'
on conflict do nothing;


-- Uma linha por tipo de ato assinavel, no nivel da opcao recomendada de D04:
-- simples para o que se resolve dentro de casa, avancada no gov.br para o que
-- sai para parceiro, orgao ou colegiado, e qualificada so para cartorio ou
-- orgao publico, que nesta rodada nenhum tipo alcanca. Sem este seed,
-- autorizacao_regras.politica_assinatura_id nasce nulo,
-- autorizacoes.nivel_assinatura_exigido cai sempre em nenhuma e a regra
-- normativa unica prometida deixa de existir. Idempotente, como os demais.
insert into public.politicas_assinatura (workspace_id, tipo_ato, nivel_exigido, exige_mfa, vigencia_inicio, decisao_id)
select w.id, a.tipo_ato::public.tipo_ato, a.nivel::public.nivel_assinatura, true, current_date, d.id
from public.workspaces w
join public.decisoes_institucionais d
  on d.workspace_id = w.id and d.codigo = 'D04' and d.status <> 'revised'
cross join (values
  ('uso_imagem',         'simples'),
  ('participacao_acao',  'simples'),
  ('ressarcimento',      'simples'),
  ('acesso_pasta',       'simples'),
  ('reativacao_vinculo', 'simples'),
  ('termo_adesao',       'simples'),
  ('termo_desligamento', 'simples'),
  ('consentimento_lgpd', 'simples'),
  ('autorizacao_imagem', 'simples'),
  ('ata_diretoria',      'simples'),
  ('parecer',            'simples'),
  ('politica',           'simples'),
  ('procedimento',       'simples'),
  ('relatorio',          'simples'),
  ('certificado',        'simples'),
  ('ata_junta',          'avancada'),
  ('ata_assembleia',     'avancada'),
  ('oficio',             'avancada'),
  ('prestacao_contas',   'avancada')
) as a(tipo_ato, nivel)
where w.kind = 'production'
on conflict do nothing;


-- ============================================================
-- 10. Contato e mural por setor
-- ============================================================

-- ============================================================================
-- Intranet CVB-RJ, parte 2 de 4: contato e mural por setor
-- Arquivo previsto: supabase/migrations/20260902120000_cvrj_intranet_contato_mural.sql
--
-- Roda depois da parte base (schemas private, auditoria, operacao e lgpd;
-- enums permissao, tipo_ato e nivel_assinatura; tabelas workspaces, profiles,
-- setores, papeis, papel_permissoes, usuario_papeis, vinculos; tabela
-- operacao.fila_emails; funcoes public.autorizar(permissao, uuid),
-- public.tocar_atualizado_em(), private.exige_aal2() e
-- private.pertence_ao_espaco(uuid)). Nada da parte base e recriado aqui.
--
-- private.pertence_ao_espaco(uuid) e a unica porta de pertencimento usada
-- nesta parte. private.is_workspace_member(uuid), da Redacao, continua
-- existindo e servindo as tabelas editoriais, mas nao e mais chamada aqui:
-- ela le public.workspace_members, e o voluntario que entrou por convite
-- nunca ganha linha nessa tabela, de modo que leria zero grupo, zero aviso e
-- zero comentario.
--
-- Origem dos padroes transpostos (desenho de tabelas, nomes de estados e
-- regras; nenhuma linha de codigo GPL ou AGPL foi copiada):
--   HumHub, protected/humhub/modules/space/models/Space.php
--     (VISIBILITY_NONE, VISIBILITY_REGISTERED_ONLY, VISIBILITY_ALL;
--      JOIN_POLICY_NONE, JOIN_POLICY_APPLICATION, JOIN_POLICY_FREE;
--      USERGROUP_OWNER, USERGROUP_ADMIN, USERGROUP_MODERATOR, USERGROUP_MEMBER)
--     e models/Membership.php (STATUS_INVITED = 1, STATUS_APPLICANT = 2,
--     STATUS_MEMBER = 3), conferidos no clone.
--   Open Social, modules/social_features/social_group/modules/
--     social_group_flexible_group (field_flexible_group_visibility com public,
--     community e members; field_group_allowed_join_method;
--     field_group_posts_enabled) e activity_creator (destinos e catalogo de
--     eventos de notificacao).
--   Jorvik (Croce Rossa Italiana), articoli/models.py, classe Articolo
--     (estratto, data_inizio_pubblicazione, data_fine_pubblicazione) e
--     segmenti/models.py, classe BaseSegmento (segmento, sede,
--     sedi_sottostanti), conferidos no clone.
--   XWiki workflow-publication, DefaultPublicationWorkflow.java
--     (estado intermediario de moderacao).
--   Plone, rolemap.xml (papeis locais), so como referencia de vocabulario.
--   Papermark, prisma/schema/document.prisma, para a ideia de anexo por
--     referencia e nunca por copia do binario.
--   Redacao CVB-RJ, supabase/migrations/20260820183726_cvrj_editorial_tables.sql
--     (notifications, messages, files), 20260820183812_cvrj_editorial_rls.sql
--     (helpers security definer no schema private, policies nomeadas) e
--     20260824190000_cvrj_mensagens_diretas.sql (recipient_id,
--     messages_destino_unico, policy messages_select_member).
--   Nielsen Norman Group e Step Two, para a governanca do mural
--     (dono nomeado, data de revisao, conteudo com dono e data).
--
-- Regra da casa: migracao so acrescenta. Nenhuma coluna, tabela ou dado da
-- Redacao e removido. Estado de ciclo de vida em ingles; taxonomia, papel e
-- acao de trilha em portugues. Nenhum dado pessoal entra na cadeia de
-- auditoria: o mural manda apenas hash do texto, UUID e codigo neutro.
-- ============================================================================


-- ============================================================================
-- 1. public.grupos
-- ============================================================================

create table if not exists public.grupos (
  id                      uuid primary key default gen_random_uuid(),
  workspace_id            uuid not null references public.workspaces (id) on delete cascade,
  tipo                    text not null check (tipo in ('setor','projeto','geral')),
  setor_id                uuid references public.setores (id) on delete restrict,
  slug                    text not null check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  nome                    text not null check (char_length(nome) between 1 and 120),
  descricao               text,
  visibilidade            text not null default 'comunidade'
                            check (visibilidade in ('publica','comunidade','membros')),
  entrada                 text not null default 'por_pedido'
                            check (entrada in ('aberta','por_pedido','por_convite')),
  status                  text not null default 'active'
                            check (status in ('active','disabled','archived')),
  modulos                 jsonb not null default
                            '{"mural":true,"biblioteca":true,"membros":true,"sobre":true,"feed":false,"chat":false}'::jsonb,
  dono_id                 uuid not null references public.profiles (id) on delete restrict,
  revisao_em              date not null default ((now() + interval '90 days')::date),
  revisado_em             timestamptz,
  exige_aprovacao_previa  boolean not null default false,
  comentarios             boolean not null default true,
  comentarios_moderados   boolean not null default true,
  fim_previsto            date,
  criado_por              uuid references public.profiles (id) on delete set null,
  criado_em               timestamptz not null default now(),
  atualizado_em           timestamptz not null default now(),
  constraint grupos_setor_conforme_tipo check (
    (tipo in ('setor','projeto') and setor_id is not null)
    or (tipo = 'geral' and setor_id is null)
  ),
  constraint grupos_fim_previsto_so_projeto check (
    tipo = 'projeto' or fim_previsto is null
  ),
  constraint grupos_slug_unico unique (workspace_id, slug)
);

-- Chave composta usada pelas filhas, para que nenhuma linha filha caia em
-- espaco diferente do grupo. Armadilha barata de evitar.
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'grupos_id_workspace_key') then
    alter table public.grupos add constraint grupos_id_workspace_key unique (id, workspace_id);
  end if;
end $$;

-- Exatamente um grupo por setor e exatamente um grupo geral por espaco.
create unique index if not exists grupos_setor_id_idx
  on public.grupos (workspace_id, setor_id) where tipo = 'setor';
create unique index if not exists grupos_tipo_geral_idx
  on public.grupos (workspace_id) where tipo = 'geral';

create index if not exists grupos_workspace_id_tipo_status_idx
  on public.grupos (workspace_id, tipo, status);
create index if not exists grupos_dono_id_idx
  on public.grupos (workspace_id, dono_id);
create index if not exists grupos_revisao_em_idx
  on public.grupos (workspace_id, revisao_em) where status = 'active';

comment on table public.grupos is
  'Grupo por setor, por projeto e o grupo geral. E o container do mural e da pasta do grupo, e guarda a governanca do mural. Nao existe tabela murais: o mural e a aba do grupo. Modelo do Space do HumHub (visibility, join_policy, status, grupos de permissao) combinado ao flexible_group do Open Social (public, community, members e metodo de entrada).';
comment on column public.grupos.tipo is
  'setor, projeto ou geral. Indice unico parcial garante um grupo de setor por setor e um unico grupo geral por espaco.';
comment on column public.grupos.visibilidade is
  'publica, comunidade ou membros. Transposto de VISIBILITY_ALL, VISIBILITY_REGISTERED_ONLY e VISIBILITY_NONE do Space do HumHub, com os nomes do field_flexible_group_visibility do Open Social. Comunidade mostra o Sobre a qualquer membro do espaco, mas o mural so a membros do grupo.';
comment on column public.grupos.entrada is
  'aberta, por_pedido ou por_convite. Transposto de JOIN_POLICY_FREE, JOIN_POLICY_APPLICATION e JOIN_POLICY_NONE do HumHub.';
comment on column public.grupos.status is
  'Ciclo de vida em ingles (active, disabled, archived), como manda a secao 9 do ARQUITETURA.md da Redacao. Grupo arquivado continua legivel.';
comment on column public.grupos.modulos is
  'Modulos ligados por grupo, no espirito de contentcontainer_permission por module_id do HumHub. feed e chat nascem desligados: fase 6 condicionada a metrica de adocao do mural.';
comment on column public.grupos.dono_id is
  'Dono nomeado do mural, exigencia dos sete elementos do Nielsen Norman Group e dos destaques da Step Two. on delete restrict porque a eliminacao LGPD anula colunas de profiles em vez de apagar a linha; transferir a propriedade e passo obrigatorio antes de qualquer remocao.';
comment on column public.grupos.revisao_em is
  'Data da proxima revisao de governanca do mural, trimestral por padrao. Vencida, gera a notificacao mural.revisao_vencida ao dono e ao administrador.';
comment on column public.grupos.exige_aprovacao_previa is
  'Transposto de category_settings.require_topic_approval do Discourse. Ligado, todo aviso de quem nao e dono, admin ou moderador do grupo passa por pending_approval.';


-- ============================================================================
-- 2. public.grupo_membros
-- ============================================================================

create table if not exists public.grupo_membros (
  id             uuid primary key default gen_random_uuid(),
  workspace_id   uuid not null references public.workspaces (id) on delete cascade,
  grupo_id       uuid not null,
  user_id        uuid not null references public.profiles (id) on delete restrict,
  papel          text not null default 'membro'
                   check (papel in ('dono','admin','moderador','membro')),
  status         text not null default 'member'
                   check (status in ('invited','applicant','member')),
  convidado_por  uuid references public.profiles (id) on delete set null,
  origem         text not null default 'manual'
                   check (origem in ('setor','manual','pedido','convite')),
  criado_em      timestamptz not null default now(),
  atualizado_em  timestamptz not null default now(),
  constraint grupo_membros_grupo_fk foreign key (grupo_id, workspace_id)
    references public.grupos (id, workspace_id) on delete cascade,
  constraint grupo_membros_unico unique (grupo_id, user_id),
  constraint grupo_membros_convite_coerente check (
    (status = 'invited' and convidado_por is not null and origem = 'convite')
    or (status <> 'invited')
  )
);

create index if not exists grupo_membros_workspace_id_user_id_idx
  on public.grupo_membros (workspace_id, user_id, status);
create index if not exists grupo_membros_grupo_id_status_idx
  on public.grupo_membros (grupo_id, status, papel);
create index if not exists grupo_membros_origem_idx
  on public.grupo_membros (grupo_id, origem) where origem = 'setor';

comment on table public.grupo_membros is
  'Pertencimento e papel de cada pessoa em cada grupo, com estado de convite e de pedido. Nao decide permissao institucional: quem decide e usuario_papeis com vinculos. Papeis do Space do HumHub (owner, admin, moderator, member) e estados do Membership do HumHub (STATUS_INVITED, STATUS_APPLICANT, STATUS_MEMBER).';
comment on column public.grupo_membros.papel is
  'Papel no grupo, em portugues porque e taxonomia e nao ciclo de vida: dono, admin, moderador, membro.';
comment on column public.grupo_membros.status is
  'Ciclo de vida em ingles: invited, applicant, member.';
comment on column public.grupo_membros.origem is
  'setor marca a linha derivada do vinculo, que o job diario recria; manual, pedido e convite sao explicitas. Sem origem nao ha como o job saber o que pode refazer.';


-- ============================================================================
-- 3. public.avisos
-- ============================================================================

create table if not exists public.avisos (
  id                 uuid primary key default gen_random_uuid(),
  workspace_id       uuid not null references public.workspaces (id) on delete cascade,
  grupo_id           uuid not null,
  autor_id           uuid not null references public.profiles (id) on delete restrict,
  titulo             text not null check (char_length(titulo) between 1 and 160),
  resumo             text check (char_length(resumo) <= 280),
  corpo              text not null,
  prioridade         text not null default 'normal'
                       check (prioridade in ('normal','importante','urgente')),
  status             text not null default 'draft'
                       check (status in ('draft','pending_approval','scheduled','published',
                                         'expired','archived','rejected')),
  vigencia_inicio    timestamptz not null default now(),
  vigencia_fim       timestamptz not null default (now() + interval '90 days'),
  fixado_ate         timestamptz,
  leitura_obrigatoria boolean not null default false,
  motivo_obrigatoriedade text
                       check (motivo_obrigatoriedade is null or motivo_obrigatoriedade in (
                         'seguranca_operacional','politica_institucional','obrigacao_legal')),
  prazo_leitura      timestamptz,
  versao             integer not null default 1 check (versao >= 1),
  anexos             uuid[] not null default '{}'::uuid[],
  fonte              text,
  coletado_em        timestamptz,
  publicado_em       timestamptz,
  aprovado_por       uuid references public.profiles (id) on delete set null,
  aprovado_em        timestamptz,
  motivo_devolucao   text,
  arquivado_em       timestamptz,
  hash_texto         text check (hash_texto is null or hash_texto ~ '^[0-9a-f]{64}$'),
  criado_em          timestamptz not null default now(),
  atualizado_em      timestamptz not null default now(),
  constraint avisos_grupo_fk foreign key (grupo_id, workspace_id)
    references public.grupos (id, workspace_id) on delete cascade,
  constraint avisos_vigencia_coerente check (vigencia_fim > vigencia_inicio),
  constraint avisos_prazo_de_leitura check (
    not leitura_obrigatoria or prazo_leitura is not null
  ),
  constraint avisos_motivo_da_obrigatoriedade check (
    not leitura_obrigatoria or motivo_obrigatoriedade is not null
  ),
  constraint avisos_devolucao_com_motivo check (
    status <> 'rejected' or motivo_devolucao is not null
  )
);

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'avisos_id_workspace_key') then
    alter table public.avisos add constraint avisos_id_workspace_key unique (id, workspace_id);
  end if;
end $$;

-- Consulta central do mural: avisos vigentes de um grupo, fixados no topo,
-- depois por prioridade e data.
create index if not exists avisos_grupo_id_status_vigencia_idx
  on public.avisos (workspace_id, grupo_id, status, vigencia_inicio desc);
create index if not exists avisos_vigentes_idx
  on public.avisos (workspace_id, grupo_id, prioridade, vigencia_inicio desc)
  where status = 'published';
create index if not exists avisos_fixados_idx
  on public.avisos (workspace_id, grupo_id, fixado_ate desc)
  where status = 'published' and fixado_ate is not null;
-- Filas do job diario de pg_cron: publicar agendado, expirar vencido,
-- arquivar expirado ha 90 dias, desafixar.
create index if not exists avisos_agendados_idx
  on public.avisos (vigencia_inicio) where status = 'scheduled';
create index if not exists avisos_a_expirar_idx
  on public.avisos (vigencia_fim) where status = 'published';
create index if not exists avisos_a_arquivar_idx
  on public.avisos (vigencia_fim) where status = 'expired';
-- Fila de moderacao e painel de governanca.
create index if not exists avisos_moderacao_idx
  on public.avisos (workspace_id, grupo_id, criado_em desc)
  where status = 'pending_approval';
create index if not exists avisos_autor_id_idx
  on public.avisos (workspace_id, autor_id, criado_em desc);
create index if not exists avisos_leitura_obrigatoria_idx
  on public.avisos (workspace_id, prazo_leitura)
  where leitura_obrigatoria and status = 'published';

comment on table public.avisos is
  'Aviso publicado no mural de um grupo, com vigencia, fixacao com data, prioridade, leitura obrigatoria com prazo e motivo, versao, anexos da biblioteca e hash do texto enviado a cadeia. Campos de vigencia e resumo transpostos de Articolo do Jorvik (estratto, data_inizio_pubblicazione, data_fine_pubblicazione); estados do Content do HumHub com o estado de moderacao do XWiki Publication Workflow. Nada e apagado: aviso arquivado continua legivel a quem podia le-lo.';
comment on column public.avisos.resumo is
  'Extrato de ate 280 caracteres, gerado do corpo quando vazio, como o estratto do Articolo do Jorvik.';
comment on column public.avisos.status is
  'Ciclo de vida em ingles: draft, pending_approval, scheduled, published, expired, archived, rejected. Traduzido na borda por lib/status-maps.ts.';
comment on column public.avisos.prioridade is
  'Taxonomia em portugues: normal, importante, urgente. So urgente gera e-mail imediato na operacao.fila_emails.';
comment on column public.avisos.fixado_ate is
  'Fixacao com data, para que nao exista aviso fixado para sempre. O job diario desafixa o que venceu.';
comment on column public.avisos.versao is
  'Incrementa a cada edicao do corpo de um aviso ja publicado. Confirmacoes anteriores continuam gravadas com a versao antiga e a pessoa recebe nova pendencia. Padrao de post_policies.version do plugin discourse-policy.';
comment on column public.avisos.anexos is
  'Ids de public.documentos da biblioteca. Nunca upload direto no aviso, para que a permissao do documento continue valendo. Nao ha chave estrangeira porque o alvo e um array e porque public.documentos nasce na parte da biblioteca: a validacao entra em migracao propria, depois das duas tabelas.';
comment on column public.avisos.hash_texto is
  'SHA-256 do corpo no momento da publicacao, unico dado do aviso que vai para auditoria.eventos no fluxo neutro do mural. Texto, titulo e autoria ficam so aqui.';
comment on column public.avisos.autor_id is
  'on delete restrict: a eliminacao LGPD anula as colunas pessoais de profiles e mantem a linha, entao o aviso nunca fica orfao nem some do mural.';
comment on column public.avisos.motivo_obrigatoriedade is
  'Taxonomia em portugues, obrigatoria quando leitura_obrigatoria e verdadeiro: seguranca_operacional, politica_institucional ou obrigacao_legal. E o que separa a cobranca que a instituicao precisa provar da cobranca que apenas mede pessoas: so seguranca_operacional e obrigacao_legal liberam a leitura nominal das linhas de aviso_leituras, e ainda assim com pessoa.ver_restrito.';
comment on column public.avisos.fonte is
  'Origem do sinal que gerou o rascunho, obrigatoria quando o autor e conta de servico (profiles.tipo_conta = servico), como o Cerebro no mural de GRD. Vazia nos avisos escritos por pessoa.';
comment on column public.avisos.coletado_em is
  'Momento em que a conta de servico coletou o sinal, obrigatorio quando o autor e conta de servico. Distinto de criado_em, que e o momento em que a linha entrou no banco.';


-- ============================================================================
-- 4. public.aviso_publicos
-- ============================================================================

create table if not exists public.aviso_publicos (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid not null references public.workspaces (id) on delete cascade,
  aviso_id      uuid not null,
  tipo          text not null check (tipo in ('todos','setor','papel','vinculo','grupo')),
  setor_id      uuid references public.setores (id) on delete restrict,
  papel         text references public.papeis (slug) on delete restrict,
  vinculo       text check (vinculo in ('colaborador','voluntario','instrutor','parceiro_externo','diretoria')),
  grupo_id      uuid references public.grupos (id) on delete restrict,
  criado_em     timestamptz not null default now(),
  constraint aviso_publicos_aviso_fk foreign key (aviso_id, workspace_id)
    references public.avisos (id, workspace_id) on delete cascade,
  constraint aviso_publicos_valor_unico check (
    (tipo = 'todos'   and setor_id is null and papel is null and vinculo is null and grupo_id is null)
    or (tipo = 'setor'   and setor_id is not null and papel is null and vinculo is null and grupo_id is null)
    or (tipo = 'papel'   and papel is not null and setor_id is null and vinculo is null and grupo_id is null)
    or (tipo = 'vinculo' and vinculo is not null and setor_id is null and papel is null and grupo_id is null)
    or (tipo = 'grupo'   and grupo_id is not null and setor_id is null and papel is null and vinculo is null)
  ),
  constraint aviso_publicos_segmento_unico unique (aviso_id, tipo, setor_id, papel, vinculo, grupo_id)
);

create index if not exists aviso_publicos_aviso_id_idx
  on public.aviso_publicos (aviso_id, tipo);
create index if not exists aviso_publicos_setor_id_idx
  on public.aviso_publicos (workspace_id, setor_id) where tipo = 'setor';
create index if not exists aviso_publicos_papel_idx
  on public.aviso_publicos (workspace_id, papel) where tipo = 'papel';
create index if not exists aviso_publicos_vinculo_idx
  on public.aviso_publicos (workspace_id, vinculo) where tipo = 'vinculo';
create index if not exists aviso_publicos_grupo_id_idx
  on public.aviso_publicos (workspace_id, grupo_id) where tipo = 'grupo';

comment on table public.aviso_publicos is
  'Segmentos de publico de um aviso por setor, papel, vinculo ou grupo, somados por uniao. Aviso sem linha alcanca todos os membros do grupo. Transposto de ArticoloSegmento e BaseSegmento do Jorvik (segmento, sede, sedi_sottostanti), com a lista fechada de segmentos virando a coluna tipo. Depois de publicado o publico so muda por nova versao.';
comment on column public.aviso_publicos.tipo is
  'todos, setor, papel, vinculo ou grupo. Exatamente uma coluna de valor preenchida, garantido por check.';
comment on column public.aviso_publicos.papel is
  'Slug de public.papeis. Papel institucional, nao papel no grupo: o publico do aviso segue a instituicao, nao o container.';


-- ============================================================================
-- 5. public.aviso_leituras
-- ============================================================================

create table if not exists public.aviso_leituras (
  id                 uuid primary key default gen_random_uuid(),
  workspace_id       uuid not null references public.workspaces (id) on delete cascade,
  aviso_id           uuid not null,
  user_id            uuid not null references public.profiles (id) on delete restrict,
  setor_id           uuid references public.setores (id) on delete set null,
  obrigatoria        boolean not null default false,
  versao             integer not null check (versao >= 1),
  visto_em           timestamptz,
  confirmado_em      timestamptz,
  lembretes_enviados integer not null default 0 check (lembretes_enviados between 0 and 3),
  ultimo_lembrete_em timestamptz,
  origem_abertura    text check (origem_abertura in ('intranet','whatsapp','email')),
  criado_em          timestamptz not null default now(),
  constraint aviso_leituras_aviso_fk foreign key (aviso_id, workspace_id)
    references public.avisos (id, workspace_id) on delete cascade,
  constraint aviso_leituras_unico unique (aviso_id, user_id, versao),
  constraint aviso_leituras_confirma_depois_de_ver check (
    confirmado_em is null or visto_em is not null
  )
);

-- Nao lidos por pessoa: bloco "O que preciso fazer" da home e a cobranca.
create index if not exists aviso_leituras_user_id_pendentes_idx
  on public.aviso_leituras (workspace_id, user_id, obrigatoria)
  where confirmado_em is null;
create index if not exists aviso_leituras_user_id_nao_vistos_idx
  on public.aviso_leituras (workspace_id, user_id)
  where visto_em is null;
-- Relatorio por setor e metrica de adocao de 30 dias.
create index if not exists aviso_leituras_aviso_id_setor_id_idx
  on public.aviso_leituras (aviso_id, setor_id, obrigatoria);
create index if not exists aviso_leituras_visto_em_idx
  on public.aviso_leituras (workspace_id, visto_em) where visto_em is not null;
-- Fila do job de lembrete: no maximo um a cada tres dias, tres por aviso.
create index if not exists aviso_leituras_lembrete_idx
  on public.aviso_leituras (aviso_id, ultimo_lembrete_em)
  where obrigatoria and confirmado_em is null;

comment on table public.aviso_leituras is
  'Quem viu e quem confirmou cada aviso, com o snapshot dos destinatarios obrigatorios feito na publicacao, para que quem entrou depois no setor nao seja cobrado nem entre na taxa. Modelo de policy_users do plugin discourse-policy (accepted_at, version, indice por politica e usuario), simplificado sem revogacao, porque ciencia de aviso nao se retira. O snapshot copia a ideia de eligible_voters do DRK Rundlaufbeschluesse.';
comment on column public.aviso_leituras.obrigatoria is
  'Verdadeiro so nas linhas criadas pelo snapshot da publicacao, feito por public.publicar_aviso. Quem entra no grupo depois ve o aviso, mas nao e cobrado nem conta na taxa.';
comment on column public.aviso_leituras.versao is
  'Versao do aviso a que a confirmacao se refere. Editar o corpo publicado cria pendencia nova sem apagar a confirmacao antiga.';
comment on column public.aviso_leituras.setor_id is
  'Setor da pessoa no momento do snapshot, congelado para o relatorio por setor. Nao acompanha transferencia posterior.';
comment on column public.aviso_leituras.origem_abertura is
  'intranet, whatsapp ou email, lido do parametro do link curto. Mede quanto do trafego vem da Comunidade do WhatsApp e alimenta o criterio de parada da fase 6.';


-- ============================================================================
-- 6. public.comentarios
-- ============================================================================

create table if not exists public.comentarios (
  id             uuid primary key default gen_random_uuid(),
  workspace_id   uuid not null references public.workspaces (id) on delete cascade,
  entidade_tipo  text not null check (entidade_tipo in ('aviso','documento')),
  entidade_id    uuid not null,
  grupo_id       uuid not null,
  parent_id      uuid references public.comentarios (id) on delete restrict,
  autor_id       uuid not null references public.profiles (id) on delete restrict,
  corpo          text not null check (char_length(corpo) between 1 and 2000),
  status         text not null default 'pending'
                   check (status in ('pending','approved','rejected','hidden')),
  moderado_por   uuid references public.profiles (id) on delete set null,
  moderado_em    timestamptz,
  motivo         text,
  criado_em      timestamptz not null default now(),
  atualizado_em  timestamptz not null default now(),
  constraint comentarios_grupo_fk foreign key (grupo_id, workspace_id)
    references public.grupos (id, workspace_id) on delete cascade,
  constraint comentarios_moderacao_coerente check (
    (status in ('pending','approved') and (moderado_por is not null or moderado_em is null))
    or (status in ('rejected','hidden') and moderado_por is not null and moderado_em is not null
        and motivo is not null)
  )
);

create index if not exists comentarios_entidade_idx
  on public.comentarios (workspace_id, entidade_tipo, entidade_id, status, criado_em);
create index if not exists comentarios_moderacao_idx
  on public.comentarios (workspace_id, grupo_id, criado_em) where status = 'pending';
create index if not exists comentarios_autor_id_idx
  on public.comentarios (workspace_id, autor_id, criado_em desc);
create index if not exists comentarios_parent_id_idx
  on public.comentarios (parent_id) where parent_id is not null;

comment on table public.comentarios is
  'Comentarios moderados em aviso e, depois, em documento, com um nivel de resposta e historico de moderacao. Tabela nova, sem relacao com content_comments da Redacao, que e comentario editorial de peca de conteudo. Historico de moderacao no espirito de reviewable_histories do Discourse; modulo comment do HumHub como referencia de container.';
comment on column public.comentarios.entidade_tipo is
  'aviso ou documento. O grupo_id fica materializado na propria linha para que a policy resolva a moderacao sem consultar o alvo.';
comment on column public.comentarios.status is
  'Ciclo de vida em ingles: pending, approved, rejected, hidden. Nasce pending quando grupos.comentarios_moderados esta ligado.';
comment on column public.comentarios.parent_id is
  'Resposta de um unico nivel. Sem curtidas, sem mencoes, sem aninhamento alem disso.';


-- ============================================================================
-- 7. public.notifications (tabela da Redacao, estendida)
--    Migracao so acrescenta: nenhuma coluna existente e tocada.
-- ============================================================================

alter table public.notifications
  add column if not exists tipo text;
alter table public.notifications
  add column if not exists entidade_tipo text;
alter table public.notifications
  add column if not exists entidade_id uuid;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'notifications_tipo_catalogo') then
    alter table public.notifications add constraint notifications_tipo_catalogo check (
      tipo is null or tipo in (
        'aviso.publicado','aviso.leitura_obrigatoria','aviso.lembrete_leitura',
        'aviso.aguardando_aprovacao','aviso.aprovado','aviso.devolvido',
        'grupo.convite','grupo.pedido','grupo.pedido_aprovado',
        'comentario.novo','comentario.aguardando_moderacao',
        'autorizacao.pendente','autorizacao.etapa_aberta','autorizacao.decidida',
        'autorizacao.prazo_vencendo','assinatura.pendente',
        'documento.nova_versao','documento.prazo_envio',
        'mensagem.nova','mural.revisao_vencida',
        'lgpd.pedido_recebido','operacao.alerta'
      )
    );
  end if;
end $$;

create index if not exists notifications_user_id_tipo_idx
  on public.notifications (workspace_id, user_id, tipo) where read_at is null;
create index if not exists notifications_entidade_idx
  on public.notifications (workspace_id, entidade_tipo, entidade_id);

comment on column public.notifications.tipo is
  'Codigo do evento no sino, no formato entidade.evento, catalogo fechado por check e espelhado em lib/auditoria/acoes.ts. Catalogo no espirito dos arquivos message.template.* do Open Social. Aceita nulo porque as linhas herdadas da Redacao nasceram sem tipo e migracao so acrescenta.';
comment on column public.notifications.entidade_tipo is
  'Tipo do objeto ligado, para agrupar e deduplicar notificacoes do mesmo alvo.';
comment on column public.notifications.entidade_id is
  'Id do objeto ligado. Sem chave estrangeira porque aponta para tabelas de partes diferentes.';
comment on table public.notifications is
  'Tabela da Redacao (20260820183726_cvrj_editorial_tables.sql), estendida. Passa a ser o catalogo de notificacao no sino. A entrega por e-mail nao mora aqui: vive inteira em operacao.fila_emails, que aponta para a notificacao.';


-- ============================================================================
-- 8. public.messages (tabela da Redacao, estendida com uma coluna)
-- ============================================================================

alter table public.messages
  add column if not exists lido_em timestamptz;

create index if not exists messages_recipient_id_lido_em_idx
  on public.messages (workspace_id, recipient_id) where lido_em is null;

comment on column public.messages.lido_em is
  'Quando o destinatario abriu a conversa. Unica coluna acrescentada as mensagens diretas da Redacao (20260824190000_cvrj_mensagens_diretas.sql): recipient_id, a constraint messages_destino_unico e a policy messages_select_member ja vieram prontas e continuam valendo. Serve so ao contador de nao lidas.';


-- ============================================================================
-- 9. Triggers
-- ============================================================================

-- 9.1 atualizado_em, no molde de touch_social_publications da Redacao.
--     A funcao public.tocar_atualizado_em() vem da parte base.
drop trigger if exists grupos_tocar on public.grupos;
create trigger grupos_tocar
  before update on public.grupos
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists grupo_membros_tocar on public.grupo_membros;
create trigger grupo_membros_tocar
  before update on public.grupo_membros
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists avisos_tocar on public.avisos;
create trigger avisos_tocar
  before update on public.avisos
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists comentarios_tocar on public.comentarios;
create trigger comentarios_tocar
  before update on public.comentarios
  for each row execute function public.tocar_atualizado_em();

-- 9.2 Versao do aviso e datas de ciclo de vida.
create or replace function public.avisos_versionar()
returns trigger language plpgsql
-- search_path vazio: funcao com search_path mutavel e vetor de sequestro de
-- nome de objeto, e o advisor do Supabase sinaliza por isso.
set search_path = ''
as $$
begin
  -- Editar o corpo de um aviso publicado incrementa a versao e cria pendencia
  -- nova de leitura. Padrao de policy_users.version do discourse-policy.
  if old.status = 'published' and new.corpo is distinct from old.corpo then
    new.versao = old.versao + 1;
  end if;

  if new.status = 'published' and old.status <> 'published' and new.publicado_em is null then
    new.publicado_em = now();
  end if;

  if new.status = 'archived' and old.status <> 'archived' and new.arquivado_em is null then
    new.arquivado_em = now();
  end if;

  return new;
end;
$$;

comment on function public.avisos_versionar() is
  'Incrementa avisos.versao quando o corpo de um aviso publicado muda e carimba publicado_em e arquivado_em. Regra do discourse-policy: a confirmacao registrada precisa corresponder ao texto lido.';

drop trigger if exists avisos_versionar on public.avisos;
create trigger avisos_versionar
  before update on public.avisos
  for each row execute function public.avisos_versionar();

-- 9.3 Leitura nao regride e snapshot nao e reescrito.
create or replace function public.aviso_leituras_nao_regride()
returns trigger language plpgsql
set search_path = ''
as $$
begin
  if new.aviso_id is distinct from old.aviso_id
     or new.user_id is distinct from old.user_id
     or new.versao is distinct from old.versao
     or new.workspace_id is distinct from old.workspace_id then
    raise exception 'aviso_leituras: aviso, pessoa, versao e espaco sao imutaveis';
  end if;

  if old.visto_em is not null and new.visto_em is null then
    raise exception 'aviso_leituras: visto_em nao volta a nulo';
  end if;

  if old.confirmado_em is not null and new.confirmado_em is distinct from old.confirmado_em then
    raise exception 'aviso_leituras: ciencia de aviso nao se retira nem se reescreve';
  end if;

  -- Snapshot da publicacao: so o job de lembrete e public.publicar_aviso
  -- (security definer, sem RLS) mexem em obrigatoria, setor_id e lembretes.
  if new.obrigatoria is distinct from old.obrigatoria
     or new.setor_id is distinct from old.setor_id then
    raise exception 'aviso_leituras: snapshot de destinatario e imutavel';
  end if;

  return new;
end;
$$;

comment on function public.aviso_leituras_nao_regride() is
  'Impede reescrever o snapshot de destinatarios e desfazer a ciencia de um aviso. Sem ele, o relatorio por setor deixaria de ser prova.';

drop trigger if exists aviso_leituras_nao_regride on public.aviso_leituras;
create trigger aviso_leituras_nao_regride
  before update on public.aviso_leituras
  for each row execute function public.aviso_leituras_nao_regride();

-- 9.4 Comentario com um unico nivel de resposta.
create or replace function public.comentarios_um_nivel()
returns trigger language plpgsql
set search_path = ''
as $$
declare
  v_avo uuid;
  v_alvo_tipo text;
  v_alvo_id uuid;
begin
  if new.parent_id is null then
    return new;
  end if;

  select c.parent_id, c.entidade_tipo, c.entidade_id
    into v_avo, v_alvo_tipo, v_alvo_id
  from public.comentarios c where c.id = new.parent_id;

  if v_avo is not null then
    raise exception 'comentarios: resposta de um nivel apenas';
  end if;

  if v_alvo_tipo is distinct from new.entidade_tipo or v_alvo_id is distinct from new.entidade_id then
    raise exception 'comentarios: resposta precisa ficar no mesmo alvo do comentario pai';
  end if;

  return new;
end;
$$;

comment on function public.comentarios_um_nivel() is
  'Limita a arvore de comentarios a um nivel de resposta e obriga a resposta a ficar no mesmo alvo. Decisao de produto do mural: sem curtidas, sem mencoes, sem aninhamento.';

drop trigger if exists comentarios_um_nivel on public.comentarios;
create trigger comentarios_um_nivel
  before insert or update on public.comentarios
  for each row execute function public.comentarios_um_nivel();

-- 9.5 Em messages, o destinatario so pode gravar lido_em.
create or replace function public.messages_so_lido_em()
returns trigger language plpgsql
set search_path = ''
as $$
begin
  if new.body is distinct from old.body
     or new.author_id is distinct from old.author_id
     or new.recipient_id is distinct from old.recipient_id
     or new.pauta_id is distinct from old.pauta_id
     or new.workspace_id is distinct from old.workspace_id
     or new.created_at is distinct from old.created_at then
    raise exception 'messages: alteracao permitida apenas em lido_em';
  end if;
  return new;
end;
$$;

comment on function public.messages_so_lido_em() is
  'Mensagem enviada nao se reescreve: o unico update aceito em public.messages e o carimbo de leitura do destinatario. A Redacao so insere, le e apaga mensagens, entao a regra nao altera comportamento existente.';

drop trigger if exists messages_so_lido_em on public.messages;
create trigger messages_so_lido_em
  before update on public.messages
  for each row execute function public.messages_so_lido_em();

-- 9.6 Conta de servico so cria rascunho, e com procedencia.
--     E o portao do Cerebro no mural de GRD: ele escreve o sinal, nunca o
--     publica. Publicar continua sendo decisao humana do dono do mural,
--     sujeita a mesma aprovacao previa dos demais avisos, o que preserva a
--     neutralidade institucional e evita credencial compartilhada em conta de
--     pessoa.
create or replace function public.avisos_conta_de_servico()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  v_tipo_conta text;
begin
  select p.tipo_conta into v_tipo_conta
  from public.profiles p where p.id = new.autor_id;

  if v_tipo_conta is distinct from 'servico' then
    return new;
  end if;

  if new.status <> 'draft' then
    raise exception 'avisos: aviso de conta de servico so existe em draft; para publicar, o dono do mural assume a autoria do aviso';
  end if;

  if new.fonte is null or btrim(new.fonte) = '' or new.coletado_em is null then
    raise exception 'avisos: aviso de conta de servico exige fonte e coletado_em preenchidos';
  end if;

  return new;
end;
$$;

comment on function public.avisos_conta_de_servico() is
  'Recusa qualquer status diferente de draft e exige fonte e coletado_em quando o autor_id aponta para perfil com profiles.tipo_conta = servico. security definer porque le profiles, que a sessao da conta de servico nao precisa enxergar inteira. Consequencia deliberada: para levar um rascunho do Cerebro a published, o dono do mural passa avisos.autor_id para o proprio uuid e assume a responsabilidade institucional pelo texto; nenhuma publicacao sai em nome de uma credencial de maquina.';

drop trigger if exists avisos_conta_de_servico on public.avisos;
create trigger avisos_conta_de_servico
  before insert or update on public.avisos
  for each row execute function public.avisos_conta_de_servico();

-- 9.7 Quem aprova assina a aprovacao com o proprio uuid.
--     A regra morava no with check de avisos_update_moderacao, que consultava
--     public.avisos para descobrir o valor antigo de aprovado_por. Policy que
--     le a propria tabela protegida e recursao infinita (42P17), e com ela
--     nenhuma sessao conseguia alterar aviso nenhum: editar rascunho, aprovar,
--     devolver, fixar e arquivar paravam todos no mesmo erro. Comparar old com
--     new e trabalho de gatilho, que ja recebe os dois valores e nao dispara
--     policy nenhuma. Defeito encontrado pela suite pgTAP do anexo 02b (teste
--     66).
create or replace function public.avisos_assinatura_da_aprovacao()
returns trigger language plpgsql
-- security definer pelo mesmo motivo de public.avisos_conta_de_servico: gatilho
-- roda com os privilegios de quem escreve, e o papel authenticated nao tem
-- usage no schema auth neste ambiente, entao auth.uid() chamada aqui sem
-- definer recusaria todo update de aviso feito pela borda. search_path vazio
-- porque funcao com search_path mutavel e vetor de sequestro de nome de objeto.
security definer
set search_path = ''
as $$
declare
  v_ator uuid := (select auth.uid());
begin
  -- Job de pg_cron e rotina de servico rodam sem JWT: nao ha assinatura a
  -- conferir, e nesses caminhos quem responde e a funcao chamadora.
  if v_ator is null then
    return new;
  end if;

  -- Manter o valor que ja estava gravado e permitido: e o que deixa outro
  -- moderador arquivar ou fixar um aviso aprovado por um colega. Trocar a
  -- assinatura por uuid de terceiro, nao.
  if new.aprovado_por is distinct from old.aprovado_por
     and new.aprovado_por is not null
     and new.aprovado_por <> v_ator then
    raise exception 'avisos: quem aprova assina a aprovacao com o proprio uuid'
      using errcode = '42501';
  end if;

  return new;
end;
$$;

comment on function public.avisos_assinatura_da_aprovacao() is
  'Recusa gravar em avisos.aprovado_por uuid que nao seja o de quem esta agindo, aceitando manter o valor anterior e limpar para nulo na devolucao. Nasceu para tirar essa comparacao do with check da policy avisos_update_moderacao, que descobria o valor antigo com um select em public.avisos e por isso caia em recursao infinita de policy (42P17), travando todo update de aviso por authenticated: o defeito foi encontrado pela suite pgTAP do anexo 02b (teste 66). Como gatilho, a regra fica mais forte do que era na policy, porque vale tambem para o caminho do autor e para as RPC security definer, e mais barata, porque compara old e new sem tocar na tabela. security definer porque gatilho executa com o privilegio de quem escreve e o papel authenticated nao alcanca o schema auth: sem isso a chamada a auth.uid() recusaria todo update de aviso vindo da borda.';

drop trigger if exists avisos_assinatura_da_aprovacao on public.avisos;
create trigger avisos_assinatura_da_aprovacao
  before update on public.avisos
  for each row execute function public.avisos_assinatura_da_aprovacao();


-- ============================================================================
-- 10. Funcoes auxiliares em private
--     Mesmo padrao das auxiliares da Redacao em
--     20260820183812_cvrj_editorial_rls.sql: security definer,
--     set search_path = '', stable, cada uma respondendo so sobre auth.uid().
--     E aqui, e nunca na policy, que se le grupo_membros, vinculos e
--     usuario_papeis.
-- ============================================================================

create or replace function private.is_grupo_membro(p_grupo_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1 from public.grupo_membros gm
    where gm.grupo_id = p_grupo_id
      and gm.user_id = (select auth.uid())
      and gm.status = 'member'
  );
$$;

create or replace function private.papel_no_grupo(p_grupo_id uuid)
returns text language sql security definer set search_path = '' stable as $$
  select gm.papel from public.grupo_membros gm
  where gm.grupo_id = p_grupo_id
    and gm.user_id = (select auth.uid())
    and gm.status = 'member'
  limit 1;
$$;

create or replace function private.aviso_visivel(p_aviso_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1
    from public.avisos a
    join public.grupos g on g.id = a.grupo_id
    where a.id = p_aviso_id
      -- Espaco, pela funcao da parte base: workspace_members nao serve, porque
      -- o voluntario que entrou por convite nunca ganha linha nela.
      and (select private.pertence_ao_espaco(a.workspace_id))
      -- So o que ja saiu da redacao aparece no mural, e o publicado so
      -- aparece dentro da janela de vigencia: o aviso cuja vigencia_fim passou
      -- ontem sai do mural no instante em que vence, sem depender de o job
      -- diario da secao 8.3 ja ter rodado. Expirado e arquivado sao historico
      -- e continuam legiveis a quem podia le-los, como diz o comentario de
      -- public.avisos, e por isso ficam fora da janela.
      -- Defeito encontrado pela suite pgTAP do anexo 02b (teste 61).
      and (
        (a.status = 'published'
         and a.vigencia_inicio <= now()
         and a.vigencia_fim > now())
        or a.status in ('expired','archived')
      )
      -- Visibilidade do grupo: publica abre o mural a qualquer membro do
      -- espaco; comunidade abre so o Sobre; membros esconde tudo.
      and (
        g.visibilidade = 'publica'
        or exists (
          select 1 from public.grupo_membros gm
          where gm.grupo_id = g.id
            and gm.user_id = (select auth.uid())
            and gm.status = 'member'
        )
      )
      -- Publico: sem segmento, alcanca todos os membros do grupo; com
      -- segmentos, vale a uniao deles (ArticoloSegmento do Jorvik).
      and (
        not exists (select 1 from public.aviso_publicos p where p.aviso_id = a.id)
        or exists (
          select 1 from public.aviso_publicos p
          where p.aviso_id = a.id
            and (
              p.tipo = 'todos'
              -- Pertencimento a setor se prova apenas por vinculo vigente.
              or (p.tipo = 'setor' and exists (
                    select 1 from public.vinculos v
                    where v.profile_id = (select auth.uid())
                      and v.setor_id = p.setor_id
                      and v.estado = 'active'
                      and (v.fim is null or v.fim > now())
                  ))
              or (p.tipo = 'papel' and exists (
                    select 1 from public.usuario_papeis up
                    where up.user_id = (select auth.uid())
                      and up.papel = p.papel
                      and up.inicio <= now()
                      and (up.fim is null or up.fim > now())
                  ))
              or (p.tipo = 'vinculo' and exists (
                    select 1 from public.vinculos v
                    where v.profile_id = (select auth.uid())
                      and v.tipo = p.vinculo
                      and v.estado = 'active'
                      and (v.fim is null or v.fim > now())
                  ))
              or (p.tipo = 'grupo' and exists (
                    select 1 from public.grupo_membros gm2
                    where gm2.grupo_id = p.grupo_id
                      and gm2.user_id = (select auth.uid())
                      and gm2.status = 'member'
                  ))
            )
        )
      )
  );
$$;

comment on function private.is_grupo_membro(uuid) is
  'Pertencimento efetivo (status member) da pessoa da sessao em um grupo. Existe para que nenhuma policy consulte grupo_membros direto, evitando a recursao que a Redacao resolve com auxiliares security definer.';
comment on function private.papel_no_grupo(uuid) is
  'Papel da pessoa da sessao no grupo: dono, admin, moderador ou membro. Papeis do Space do HumHub.';
comment on function private.aviso_visivel(uuid) is
  'Combina estado e vigencia do aviso, pertencimento ao espaco por private.pertence_ao_espaco, visibilidade do grupo, pertencimento ao grupo e os segmentos de aviso_publicos com setor, papel, vinculo e grupos da pessoa da sessao. E a unica porta de leitura do mural. No segmento de setor, a prova de pertencimento e apenas public.vinculos com estado active e fim nulo ou futuro: profiles.setor_principal_id nao vale como prova porque a policy profiles_update_self da Redacao deixa a propria pessoa gravar essa coluna, e um voluntario que se colocasse no setor Diretoria passaria a ler os avisos segmentados a ela. A vigencia entra na propria condicao de leitura, e nao so no job diario: aviso em published aparece apenas entre vigencia_inicio e vigencia_fim, porque o cron roda uma vez por dia e a visibilidade nao pode depender de ele ja ter passado; expired e archived, que sao historico, ficam fora dessa janela e continuam legiveis. Defeito encontrado pela suite pgTAP do anexo 02b (teste 61).';

revoke all on function private.is_grupo_membro(uuid) from public, anon;
revoke all on function private.papel_no_grupo(uuid)  from public, anon;
revoke all on function private.aviso_visivel(uuid)   from public, anon;

grant execute on function private.is_grupo_membro(uuid) to authenticated;
grant execute on function private.papel_no_grupo(uuid)  to authenticated;
grant execute on function private.aviso_visivel(uuid)   to authenticated;


-- ============================================================================
-- 11. RLS ligado, na mesma migracao que cria as tabelas
-- ============================================================================

alter table public.grupos          enable row level security;
alter table public.grupo_membros   enable row level security;
alter table public.avisos          enable row level security;
alter table public.aviso_publicos  enable row level security;
alter table public.aviso_leituras  enable row level security;
alter table public.comentarios     enable row level security;
-- notifications e messages ja estao com RLS ligado desde a Redacao.


-- ============================================================================
-- 12. Policies (todas to authenticated; anon nunca recebe policy)
--     Pertencimento ao espaco sempre por private.pertence_ao_espaco, da parte
--     base, nunca por private.is_workspace_member.
-- ============================================================================

-- ---------- grupos ----------
drop policy if exists grupos_select_visivel on public.grupos;
create policy grupos_select_visivel on public.grupos for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      visibilidade in ('publica','comunidade')
      or (select private.is_grupo_membro(id))
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
      or (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
    )
  );

drop policy if exists grupos_insert_autorizado on public.grupos;
create policy grupos_insert_autorizado on public.grupos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and criado_por = (select auth.uid())
    and status = 'active'
    and (
      -- Coordenador cria grupo de projeto do proprio setor sem passar pelo
      -- administrador, para nao criar gargalo no unico admin tecnico.
      (tipo = 'projeto' and (select public.autorizar('grupo.criar'::public.permissao, setor_id)))
      -- Grupo de setor e grupo geral so por quem administra grupos.
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  );

drop policy if exists grupos_update_dono on public.grupos;
create policy grupos_update_dono on public.grupos for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(id)) in ('dono','admin')
      or (select public.autorizar('grupo.administrar'::public.permissao, setor_id))
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(id)) in ('dono','admin')
      or (select public.autorizar('grupo.administrar'::public.permissao, setor_id))
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  );

-- Sem policy de delete: arquivar e update de status.

comment on policy grupos_select_visivel on public.grupos is
  'Grupo publico ou de comunidade aparece a qualquer membro do espaco; grupo de visibilidade membros so a quem pertence. Auditor le tudo por trilha.ler_completa e nunca escreve.';
comment on policy grupos_insert_autorizado on public.grupos is
  'Coordenador abre grupo de projeto do proprio setor com grupo.criar; grupo de setor e o grupo geral exigem grupo.administrar global. A autoria fica fixada em criado_por.';


-- ---------- grupo_membros ----------
drop policy if exists grupo_membros_select_grupo on public.grupo_membros;
create policy grupo_membros_select_grupo on public.grupo_membros for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      user_id = (select auth.uid())
      or (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (status = 'member' and (select private.is_grupo_membro(grupo_id)))
      or (status = 'member' and exists (
            select 1 from public.grupos g
            where g.id = grupo_id and g.visibilidade = 'publica'
          ))
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
      or (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
    )
  );

drop policy if exists grupo_membros_insert_proprio on public.grupo_membros;
create policy grupo_membros_insert_proprio on public.grupo_membros for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
    and papel = 'membro'
    and convidado_por is null
    and (select g.status from public.grupos g where g.id = grupo_id) = 'active'
    and (
      (origem = 'manual' and status = 'member'
        and (select g.entrada from public.grupos g where g.id = grupo_id) = 'aberta')
      or (origem = 'pedido' and status = 'applicant'
        and (select g.entrada from public.grupos g where g.id = grupo_id) = 'por_pedido')
    )
  );

drop policy if exists grupo_membros_insert_convite on public.grupo_membros;
create policy grupo_membros_insert_convite on public.grupo_membros for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and status = 'invited'
    and origem = 'convite'
    and convidado_por = (select auth.uid())
    and papel <> 'dono'
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin')
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  );

drop policy if exists grupo_membros_update_gestao on public.grupo_membros;
create policy grupo_membros_update_gestao on public.grupo_membros for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin')
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin')
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  );

drop policy if exists grupo_membros_update_proprio on public.grupo_membros;
create policy grupo_membros_update_proprio on public.grupo_membros for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
    and status = 'invited'
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
    and status = 'member'
    and papel = 'membro'
  );

drop policy if exists grupo_membros_delete_saida on public.grupo_membros;
create policy grupo_membros_delete_saida on public.grupo_membros for delete to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      -- Sair do grupo. O dono nao sai sem transferir a propriedade antes.
      (user_id = (select auth.uid()) and papel <> 'dono')
      -- Remover membro, ou recusar pedido.
      or ((select private.papel_no_grupo(grupo_id)) in ('dono','admin') and papel <> 'dono')
      or (select public.autorizar('grupo.administrar'::public.permissao, null::uuid))
    )
  );

comment on policy grupo_membros_insert_proprio on public.grupo_membros is
  'Entrada aberta entra direto como member; entrada por_pedido entra como applicant. Transposto de JOIN_POLICY_FREE e JOIN_POLICY_APPLICATION do HumHub.';
comment on policy grupo_membros_delete_saida on public.grupo_membros is
  'Um dos quatro unicos delete de authenticated da intranet: sair do grupo. Dono precisa transferir a propriedade antes, para que nenhum mural fique sem dono.';


-- ---------- avisos ----------
drop policy if exists avisos_select_visivel on public.avisos;
create policy avisos_select_visivel on public.avisos for select to authenticated
  using ((select private.aviso_visivel(id)));

drop policy if exists avisos_select_gestao on public.avisos;
create policy avisos_select_gestao on public.avisos for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      autor_id = (select auth.uid())
      or (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (select public.autorizar('mural.moderar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = avisos.grupo_id)))
      or (select public.autorizar('mural.ver_relatorio'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = avisos.grupo_id)))
      or (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
    )
  );

drop policy if exists avisos_insert_membro on public.avisos;
create policy avisos_insert_membro on public.avisos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    and (select private.is_grupo_membro(grupo_id))
    and (select g.status from public.grupos g where g.id = grupo_id) = 'active'
    and status in ('draft','pending_approval')
    and versao = 1
    and publicado_em is null
    and aprovado_por is null
    and aprovado_em is null
    and arquivado_em is null
  );

drop policy if exists avisos_update_autor on public.avisos;
create policy avisos_update_autor on public.avisos for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    and status in ('draft','pending_approval','rejected')
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    -- O autor manda a minuta para aprovacao, nunca publica sozinho.
    and status in ('draft','pending_approval')
    and aprovado_por is null
  );

drop policy if exists avisos_update_moderacao on public.avisos;
create policy avisos_update_moderacao on public.avisos for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (select public.autorizar('mural.aprovar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = avisos.grupo_id)))
      or (select public.autorizar('mural.moderar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = avisos.grupo_id)))
    )
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (select public.autorizar('mural.aprovar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = avisos.grupo_id)))
      or (select public.autorizar('mural.moderar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = avisos.grupo_id)))
    )
    -- Publicar aviso oficial e decisao: exige sessao com MFA verificada.
    -- O caminho normal de publicacao e a RPC public.publicar_aviso, que faz o
    -- snapshot de leitura, as notificacoes e a fila de e-mail na mesma
    -- transacao; esta policy cobre a publicacao manual e o arquivamento.
    and (status <> 'published' or (select private.exige_aal2()))
    -- A assinatura da aprovacao (aprovado_por so recebe o uuid de quem aprova)
    -- saiu daqui para o gatilho public.avisos_assinatura_da_aprovacao: a regra
    -- compara o valor antigo com o novo, e ler avisos de dentro de uma policy
    -- de avisos era recursao infinita (42P17) que travava todo update da
    -- tabela. Defeito encontrado pela suite pgTAP do anexo 02b (teste 66).
  );

-- Sem policy de delete: arquivar e update de status e de arquivado_em.

comment on policy avisos_select_visivel on public.avisos is
  'Leitura do mural por private.aviso_visivel: publicado dentro da janela de vigencia, ou expirado ou arquivado, mais visibilidade do grupo, mais a uniao dos segmentos de aviso_publicos. A janela de vigencia entrou na funcao porque a suite pgTAP do anexo 02b (teste 61) mostrou aviso com vigencia encerrada ontem ainda visivel ao destinatario.';
comment on policy avisos_update_moderacao on public.avisos is
  'Publicar, aprovar, devolver e arquivar. Levar o aviso a published exige private.exige_aal2(), a mesma regra das demais decisoes da intranet. A conferencia de aprovado_por nao mora mais aqui: comparar o valor antigo com o novo obrigava a policy a consultar public.avisos, o que e recursao infinita em policy (42P17) e travava todo update de aviso, defeito encontrado pela suite pgTAP do anexo 02b (teste 66). A regra passou integra para o gatilho before update public.avisos_assinatura_da_aprovacao, que ja tem old e new em maos e vale para todo caminho de escrita, inclusive o do autor.';


-- ---------- aviso_publicos ----------
drop policy if exists aviso_publicos_select_aviso on public.aviso_publicos;
create policy aviso_publicos_select_aviso on public.aviso_publicos for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and exists (select 1 from public.avisos a where a.id = aviso_id)
  );

drop policy if exists aviso_publicos_insert_redacao on public.aviso_publicos;
create policy aviso_publicos_insert_redacao on public.aviso_publicos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and exists (
      select 1 from public.avisos a
      where a.id = aviso_id
        and a.workspace_id = aviso_publicos.workspace_id
        -- Depois de publicado o publico so muda por nova versao.
        and a.status in ('draft','pending_approval','rejected')
        and (
          a.autor_id = (select auth.uid())
          or (select private.papel_no_grupo(a.grupo_id)) in ('dono','admin','moderador')
        )
    )
  );

drop policy if exists aviso_publicos_update_redacao on public.aviso_publicos;
create policy aviso_publicos_update_redacao on public.aviso_publicos for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and exists (
      select 1 from public.avisos a
      where a.id = aviso_id
        and a.status in ('draft','pending_approval','rejected')
        and (
          a.autor_id = (select auth.uid())
          or (select private.papel_no_grupo(a.grupo_id)) in ('dono','admin','moderador')
        )
    )
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and exists (
      select 1 from public.avisos a
      where a.id = aviso_id
        and a.status in ('draft','pending_approval','rejected')
        and (
          a.autor_id = (select auth.uid())
          or (select private.papel_no_grupo(a.grupo_id)) in ('dono','admin','moderador')
        )
    )
  );

-- Sem policy de delete, pela regra de que so quatro tabelas da intranet
-- aceitam delete de authenticated. Retirar um segmento antes da publicacao e
-- feito pela funcao security definer da Server Action que reescreve o publico
-- inteiro do aviso.

comment on policy aviso_publicos_insert_redacao on public.aviso_publicos is
  'Segmentos de publico so entram enquanto o aviso e minuta, esta aguardando aprovacao ou foi devolvido. Depois de published, mudar o publico exige nova versao do aviso.';


-- ---------- aviso_leituras ----------
drop policy if exists aviso_leituras_select_propria on public.aviso_leituras;
create policy aviso_leituras_select_propria on public.aviso_leituras for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
  );

drop policy if exists aviso_leituras_select_relatorio on public.aviso_leituras;
create policy aviso_leituras_select_relatorio on public.aviso_leituras for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    -- Linha individual carrega user_id: e historico nominal de leitura, nao
    -- numero agregado. So sai com pessoa.ver_restrito.
    and (select public.autorizar('pessoa.ver_restrito'::public.permissao, null::uuid))
    and exists (
      select 1 from public.avisos a
      where a.id = aviso_id
        -- E so quando a obrigatoriedade do aviso tem motivo que justifique
        -- guardar nome: seguranca operacional ou obrigacao legal.
        and a.motivo_obrigatoriedade in ('seguranca_operacional','obrigacao_legal')
        and (
          -- A secao 8.2 do escopo nomeia quem le a lista nominal de quem nao
          -- confirmou: "apenas a secretaria e a administrador". A linha da
          -- secretaria em 5.2 repete o mesmo ("ve a lista nominal de leitura
          -- pendente"). A correcao ficou na policy, e nao no seed de
          -- papel_permissoes: dar mural.ver_relatorio a secretaria faria a
          -- Secretaria passar tambem por avisos_select_gestao, lendo o rascunho
          -- e o aviso devolvido de todos os murais, e por
          -- public.relatorio_leitura_aviso em todos os setores, dois alcances
          -- que nem 8.2 nem 5.2 lhe dao. Nomear os dois papeis por
          -- private.tem_papel e a excecao ja declarada no comentario dessa
          -- funcao, para quando a permissao nomeada nao basta. Continuam
          -- valendo, para todos, pessoa.ver_restrito e o motivo de
          -- obrigatoriedade restrito a seguranca operacional ou obrigacao
          -- legal. Defeito encontrado pela suite pgTAP do anexo 02b (teste 100).
          (select private.tem_papel('secretaria'))
          or (select private.tem_papel('administrador'))
          or a.autor_id = (select auth.uid())
          or (select private.papel_no_grupo(a.grupo_id)) in ('dono','admin','moderador')
          or (select public.autorizar('mural.ver_relatorio'::public.permissao,
                (select g.setor_id from public.grupos g where g.id = a.grupo_id)))
          or (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
        )
    )
  );

drop policy if exists aviso_leituras_insert_propria on public.aviso_leituras;
create policy aviso_leituras_insert_propria on public.aviso_leituras for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
    and (select private.aviso_visivel(aviso_id))
    -- O snapshot obrigatorio nasce so na publicacao, dentro de
    -- public.publicar_aviso. Pela porta do usuario entra apenas a leitura
    -- espontanea.
    and obrigatoria = false
    and confirmado_em is null
    and lembretes_enviados = 0
    and ultimo_lembrete_em is null
    and versao = (select a.versao from public.avisos a where a.id = aviso_id)
  );

drop policy if exists aviso_leituras_update_propria on public.aviso_leituras;
create policy aviso_leituras_update_propria on public.aviso_leituras for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
  );

-- Sem policy de delete: registro de leitura e prova e nao se apaga.

comment on policy aviso_leituras_insert_propria on public.aviso_leituras is
  'Marcar como visto e ato da propria pessoa. O snapshot de destinatarios obrigatorios da publicacao entra por public.publicar_aviso, security definer, fora do alcance do cliente, para que a taxa do relatorio nao possa ser fabricada.';
comment on policy aviso_leituras_select_relatorio on public.aviso_leituras is
  'Numero, percentual e distribuicao por setor continuam disponiveis ao autor, ao dono, admin e moderador do grupo e a quem tem mural.ver_relatorio no setor, mas pela funcao agregada public.relatorio_leitura_aviso, que nunca devolve user_id. A leitura das linhas individuais, essas sim nominais, exige pessoa.ver_restrito e aviso com motivo_obrigatoriedade igual a seguranca_operacional ou obrigacao_legal. O motivo: historico nominal de atraso de leitura cobrado de quem presta servico voluntario aproxima o registro de controle de jornada e excede a minimizacao do art. 6, III, da LGPD. Alem disso a policy nomeia agora, por private.tem_papel, os dois papeis a quem a secao 8.2 reserva a lista nominal, secretaria e administrador: o seed dava a secretaria so mural.publicar e ela ficava sem a lista que 5.2 lhe atribui. A correcao ficou aqui, e nao no seed de papel_permissoes, porque conceder mural.ver_relatorio a secretaria a levaria tambem a avisos_select_gestao e ao relatorio agregado de todos os setores, alcances que o escopo nao lhe da. Defeito encontrado pela suite pgTAP do anexo 02b (teste 100).';


-- ---------- comentarios ----------
drop policy if exists comentarios_select_alvo on public.comentarios;
create policy comentarios_select_alvo on public.comentarios for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      autor_id = (select auth.uid())
      or (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (select public.autorizar('mural.moderar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = comentarios.grupo_id)))
      or (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
      or (
        status = 'approved'
        and (
          (entidade_tipo = 'aviso' and (select private.aviso_visivel(entidade_id)))
          -- Comentario em documento entra depois, com a biblioteca. Ate la a
          -- leitura fica presa ao grupo dono do alvo; a troca por
          -- private.pode_ver_documento entra em migracao propria, depois das
          -- duas tabelas.
          or (entidade_tipo = 'documento' and (select private.is_grupo_membro(grupo_id)))
        )
      )
    )
  );

drop policy if exists comentarios_insert_membro on public.comentarios;
create policy comentarios_insert_membro on public.comentarios for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    and (select private.is_grupo_membro(grupo_id))
    and (select g.status from public.grupos g where g.id = grupo_id) = 'active'
    and (select g.comentarios from public.grupos g where g.id = grupo_id)
    and moderado_por is null
    and moderado_em is null
    and motivo is null
    and status = (
      case when (select g.comentarios_moderados from public.grupos g where g.id = grupo_id)
           then 'pending' else 'approved' end
    )
  );

drop policy if exists comentarios_update_autor on public.comentarios;
create policy comentarios_update_autor on public.comentarios for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    and status = 'pending'
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    and status = 'pending'
    and moderado_por is null
    and moderado_em is null
  );

drop policy if exists comentarios_update_moderacao on public.comentarios;
create policy comentarios_update_moderacao on public.comentarios for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (select public.autorizar('mural.moderar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = comentarios.grupo_id)))
    )
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      (select private.papel_no_grupo(grupo_id)) in ('dono','admin','moderador')
      or (select public.autorizar('mural.moderar'::public.permissao,
            (select g.setor_id from public.grupos g where g.id = comentarios.grupo_id)))
    )
    and (status = 'pending' or moderado_por = (select auth.uid()))
  );

drop policy if exists comentarios_delete_autor on public.comentarios;
create policy comentarios_delete_autor on public.comentarios for delete to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and autor_id = (select auth.uid())
    and status = 'pending'
  );

comment on policy comentarios_insert_membro on public.comentarios is
  'Comentario nasce pending quando o grupo modera e approved quando nao modera, exatamente como grupos.comentarios_moderados manda. Sem comentarios ligados no grupo, ninguem escreve.';
comment on policy comentarios_delete_autor on public.comentarios is
  'Um dos quatro unicos delete de authenticated da intranet: o autor desiste do proprio comentario enquanto ele ainda esta na fila de moderacao. Depois de aprovado, so se oculta.';


-- ---------- notifications (tabela da Redacao) ----------
-- A Redacao nunca criou policy de insert para notifications, e a intranet
-- passa a escrever no sino por Server Action autenticada. A policy fixa a
-- autoria: ninguem notifica em nome de outra pessoa. Notificar terceiro e
-- competencia de public.registrar_notificacoes.
drop policy if exists notifications_insert_own on public.notifications;
create policy notifications_insert_own on public.notifications for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and user_id = (select auth.uid())
  );

comment on policy notifications_insert_own on public.notifications is
  'Notificar terceiro e feito por public.registrar_notificacoes e por public.publicar_aviso, funcoes security definer chamadas de dentro de RPC de transicao ja autorizada, nunca pelo cliente. As policies notifications_select_own e notifications_update_own da Redacao continuam intactas.';


-- ---------- messages (tabela da Redacao) ----------
-- A policy generica messages_update_member da Redacao (criada no laco de
-- 20260820183812) deixa qualquer membro do espaco alterar qualquer mensagem.
-- Ela NAO e derrubada aqui: derrubar policy de tabela em producao e migracao
-- subtrativa, e a regra da casa (armadilha 10.1 do ARQUITETURA.md) manda que
-- isso saia em arquivo proprio marcado -- limpeza:, depois do deploy que
-- parou de depender dela.
--
-- limpeza: pendencia "derrubar public.messages_update_member", em migracao
-- propria posterior ao deploy em que a Redacao e a intranet passarem a gravar
-- lido_em apenas pela policy messages_update_destinatario. Enquanto ela
-- existir, o trigger public.messages_so_lido_em ja garante que nenhuma coluna
-- alem de lido_em muda; o que continua largo e apenas quem pode carimbar a
-- leitura.
drop policy if exists messages_update_destinatario on public.messages;
create policy messages_update_destinatario on public.messages for update to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and recipient_id = (select auth.uid())
  )
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and recipient_id = (select auth.uid())
  );

comment on policy messages_update_destinatario on public.messages is
  'So o destinatario de uma conversa direta marca a leitura, e o trigger messages_so_lido_em garante que nada alem de lido_em muda. Convive com a policy larga messages_update_member da Redacao ate a migracao de limpeza que a derruba.';


-- ============================================================================
-- 13. RPCs de transicao (security definer, set search_path = '')
--     Existem porque as policies desta parte fecham por padrao: aviso_leituras
--     proibe obrigatoria = true pela porta do cliente e notifications proibe
--     insert com user_id de terceiro. Sem estas funcoes, leitura obrigatoria e
--     notificacao de destinatario nao teriam caminho de criacao nenhum.
-- ============================================================================

-- 13.1 Publicacao do aviso: uma transacao, cinco efeitos.
create or replace function public.publicar_aviso(p_aviso_id uuid)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_ator             uuid := (select auth.uid());
  v_aviso            public.avisos;
  v_grupo            public.grupos;
  v_tipo             text;
  v_prioridade_email text;
  v_total            integer := 0;
  v_agendar          boolean;
  v_destinatarios    uuid[];
begin
  if v_ator is null then
    raise exception 'publicar_aviso: sem sessao';
  end if;

  select a.* into v_aviso from public.avisos a where a.id = p_aviso_id for update;
  if not found then
    raise exception 'publicar_aviso: aviso % nao encontrado', p_aviso_id;
  end if;

  select g.* into v_grupo from public.grupos g where g.id = v_aviso.grupo_id;

  if not (select private.pertence_ao_espaco(v_aviso.workspace_id)) then
    raise exception 'publicar_aviso: fora do espaco do aviso';
  end if;

  -- Autorizacao no setor do grupo, e nao no setor de quem chama.
  if not (select public.autorizar('mural.publicar'::public.permissao, v_grupo.setor_id)) then
    raise exception 'publicar_aviso: exige a permissao mural.publicar no setor do grupo';
  end if;

  -- Publicar aviso oficial e decisao: sessao com MFA verificada.
  if not (select private.exige_aal2()) then
    raise exception 'publicar_aviso: exige sessao com MFA verificada (aal2)';
  end if;

  if v_grupo.status <> 'active' then
    raise exception 'publicar_aviso: grupo em % nao recebe publicacao', v_grupo.status;
  end if;

  if v_aviso.status not in ('draft','pending_approval','scheduled') then
    raise exception 'publicar_aviso: aviso em % nao pode ser publicado', v_aviso.status;
  end if;

  if v_aviso.leitura_obrigatoria and v_aviso.motivo_obrigatoriedade is null then
    raise exception 'publicar_aviso: leitura obrigatoria exige motivo_obrigatoriedade';
  end if;

  -- 1. Estado e carimbo. Aviso cuja vigencia so comeca depois de hoje nao vira
  --    publicacao imediata: entra em scheduled e o job diario de pg_cron o
  --    publica no dia de vigencia_inicio, que e a transicao "draft para
  --    scheduled quando vigencia_inicio e futura" e "scheduled para published
  --    pelo cron" da secao 8.3 do escopo, o mesmo estado que o indice parcial
  --    avisos_agendados_idx ja preve. Defeito encontrado pela suite pgTAP do
  --    anexo 02b (teste 79).
  v_agendar := v_aviso.vigencia_inicio > now();

  update public.avisos a
     set status       = case when v_agendar then 'scheduled' else 'published' end,
         publicado_em = case when v_agendar then a.publicado_em
                             else coalesce(a.publicado_em, now()) end
   where a.id = v_aviso.id
  returning a.* into v_aviso;

  -- 2. Destinatarios: os segmentos de aviso_publicos resolvidos em pessoas, na
  --    uniao (ArticoloSegmento do Jorvik). Sem segmento, todos os membros do
  --    grupo. Pertencimento a setor prova-se por vinculo vigente, nunca por
  --    profiles.setor_principal_id.
  select array_agg(d.user_id) into v_destinatarios
  from (
    select distinct gm.user_id
    from public.grupo_membros gm
    join public.profiles pf on pf.id = gm.user_id
    where gm.grupo_id = v_aviso.grupo_id
      and gm.status = 'member'
      and pf.desativado_em is null
      and pf.eliminado_em is null
      and (
        not exists (select 1 from public.aviso_publicos p where p.aviso_id = v_aviso.id)
        or exists (
          select 1 from public.aviso_publicos p
          where p.aviso_id = v_aviso.id
            and (
              p.tipo = 'todos'
              or (p.tipo = 'setor' and exists (
                    select 1 from public.vinculos v
                    where v.profile_id = gm.user_id
                      and v.setor_id = p.setor_id
                      and v.estado = 'active'
                      and (v.fim is null or v.fim > now())
                  ))
              or (p.tipo = 'papel' and exists (
                    select 1 from public.usuario_papeis up
                    where up.user_id = gm.user_id
                      and up.papel = p.papel
                      and up.inicio <= now()
                      and (up.fim is null or up.fim > now())
                  ))
              or (p.tipo = 'vinculo' and exists (
                    select 1 from public.vinculos v
                    where v.profile_id = gm.user_id
                      and v.tipo = p.vinculo
                      and v.estado = 'active'
                      and (v.fim is null or v.fim > now())
                  ))
              or (p.tipo = 'grupo' and exists (
                    select 1 from public.grupo_membros gm2
                    where gm2.grupo_id = p.grupo_id
                      and gm2.user_id = gm.user_id
                      and gm2.status = 'member'
                  ))
            )
        )
      )
  ) d;

  v_total := coalesce(array_length(v_destinatarios, 1), 0);

  -- Agendado para o futuro: nada de snapshot, sino nem fila de e-mail hoje. O
  -- congelamento da lista e o setor_id "daquele instante" da secao 8.2 sao do
  -- instante da publicacao, entao quem entrar no mural ate la ainda entra na
  -- foto, e a cobranca de leitura nao comeca antes de o aviso existir no mural.
  -- Devolve o alcance de hoje, que e o que a tela de agendamento mostra.
  if v_agendar then
    return v_total;
  end if;

  -- 3. Snapshot dos destinatarios, congelado no instante da publicacao.
  insert into public.aviso_leituras (
    workspace_id, aviso_id, user_id, setor_id, obrigatoria, versao
  )
  select
    v_aviso.workspace_id,
    v_aviso.id,
    d.user_id,
    (select v.setor_id from public.vinculos v
      where v.profile_id = d.user_id
        and v.estado = 'active'
        and (v.fim is null or v.fim > now())
      order by v.inicio desc
      limit 1),
    v_aviso.leitura_obrigatoria,
    v_aviso.versao
  from unnest(v_destinatarios) as d(user_id)
  on conflict (aviso_id, user_id, versao) do nothing;

  select count(*) into v_total
  from public.aviso_leituras l
  where l.aviso_id = v_aviso.id and l.versao = v_aviso.versao;

  v_tipo := case when v_aviso.leitura_obrigatoria
                 then 'aviso.leitura_obrigatoria'
                 else 'aviso.publicado' end;

  -- So urgente sai na hora; o resto espera o digest diario, que e o que
  -- mantem o envio dentro do orcamento gratuito do Resend.
  v_prioridade_email := case when v_aviso.prioridade = 'urgente'
                             then 'imediato' else 'resumo' end;

  -- 4 e 5. Sino e fila de e-mail, na mesma instrucao, para que nenhuma
  --        notificacao fique sem entrega e nenhuma entrega fique sem sino.
  with novas as (
    insert into public.notifications (
      workspace_id, user_id, title, message, link, tipo, entidade_tipo, entidade_id
    )
    select
      l.workspace_id,
      l.user_id,
      v_aviso.titulo,
      v_aviso.resumo,
      '/mural/' || v_grupo.slug || '/avisos/' || v_aviso.id::text,
      v_tipo,
      'aviso',
      v_aviso.id
    from public.aviso_leituras l
    where l.aviso_id = v_aviso.id
      and l.versao = v_aviso.versao
    returning id, workspace_id, user_id
  )
  insert into operacao.fila_emails (
    workspace_id, destinatario_id, notificacao_id, tipo,
    entidade_tipo, entidade_id, prioridade, status
  )
  select n.workspace_id, n.user_id, n.id, v_tipo, 'aviso', v_aviso.id,
         v_prioridade_email, 'queued'
  from novas n;

  return v_total;
end;
$$;

comment on function public.publicar_aviso(uuid) is
  'Publica um aviso e faz, na mesma transacao: confere public.autorizar(mural.publicar, setor do grupo) e private.exige_aal2(); quando vigencia_inicio ainda e futura move o aviso para scheduled, sem carimbar publicado_em e sem snapshot, notificacao ou fila de e-mail, deixando a publicacao para o job diario da secao 8.3, e devolve so o alcance de hoje, defeito encontrado pela suite pgTAP do anexo 02b (teste 79); nos demais casos move o aviso de draft, pending_approval ou scheduled para published carimbando publicado_em; resolve os segmentos de aviso_publicos em pessoas; grava o snapshot em aviso_leituras com obrigatoria igual a avisos.leitura_obrigatoria, versao igual a versao corrente e setor_id do instante; insere as linhas de notifications dos destinatarios; e enfileira operacao.fila_emails com prioridade imediato quando o aviso e urgente e resumo nos demais casos. Existe porque a policy aviso_leituras_insert_propria proibe obrigatoria = true: sem esta funcao, a leitura obrigatoria nao teria caminho de criacao nenhum. Devolve o numero de destinatarios do snapshot.';

-- 13.2 Notificacao de terceiro, o que a policy notifications_insert_own veda.
create or replace function public.registrar_notificacoes(
  p_tipo           text,
  p_entidade_tipo  text,
  p_entidade_id    uuid,
  p_destinatarios  uuid[]
)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_ator             uuid := (select auth.uid());
  v_workspace        uuid;
  v_definicao        text;
  v_prioridade_email text;
  v_total            integer := 0;
begin
  if v_ator is null then
    raise exception 'registrar_notificacoes: sem sessao';
  end if;

  if p_destinatarios is null or array_length(p_destinatarios, 1) is null then
    return 0;
  end if;

  -- Espaco unico da intranet, como a Redacao ja opera desde a migracao
  -- 20260824163949_cvrj_remove_espaco_demonstracao.sql.
  select w.id into v_workspace from public.workspaces w where w.slug = 'producao';
  if v_workspace is null then
    raise exception 'registrar_notificacoes: espaco producao ausente';
  end if;

  if not (select private.pertence_ao_espaco(v_workspace)) then
    raise exception 'registrar_notificacoes: fora do espaco';
  end if;

  -- Tipo conferido contra a propria constraint notifications_tipo_catalogo,
  -- para que o catalogo nao seja reescrito aqui e nao possa divergir dela.
  select pg_catalog.pg_get_constraintdef(c.oid) into v_definicao
  from pg_catalog.pg_constraint c
  join pg_catalog.pg_class t on t.oid = c.conrelid
  join pg_catalog.pg_namespace n on n.oid = t.relnamespace
  where n.nspname = 'public'
    and t.relname = 'notifications'
    and c.conname = 'notifications_tipo_catalogo';

  if v_definicao is null then
    raise exception 'registrar_notificacoes: constraint notifications_tipo_catalogo ausente';
  end if;

  if p_tipo is null
     or position(pg_catalog.quote_literal(p_tipo) in v_definicao) = 0 then
    raise exception 'registrar_notificacoes: tipo % fora do catalogo notifications_tipo_catalogo', p_tipo;
  end if;

  v_prioridade_email := case
    when p_tipo in ('grupo.convite','autorizacao.pendente') then 'imediato'
    else 'resumo'
  end;

  with alvos as (
    select distinct pf.id as user_id
    from unnest(p_destinatarios) as d(user_id)
    join public.profiles pf on pf.id = d.user_id
    where pf.desativado_em is null
      and pf.eliminado_em is null
  ),
  novas as (
    insert into public.notifications (
      workspace_id, user_id, title, message, link, tipo, entidade_tipo, entidade_id
    )
    select v_workspace, a.user_id, p_tipo, null, null, p_tipo, p_entidade_tipo, p_entidade_id
    from alvos a
    returning id, workspace_id, user_id
  )
  insert into operacao.fila_emails (
    workspace_id, destinatario_id, notificacao_id, tipo,
    entidade_tipo, entidade_id, prioridade, status
  )
  select n.workspace_id, n.user_id, n.id, p_tipo, p_entidade_tipo, p_entidade_id,
         v_prioridade_email, 'queued'
  from novas n;

  get diagnostics v_total = row_count;
  return v_total;
end;
$$;

comment on function public.registrar_notificacoes(text, text, uuid, uuid[]) is
  'Insere uma linha de public.notifications por destinatario, com tipo conferido contra a constraint notifications_tipo_catalogo, e a linha correspondente em operacao.fila_emails. Existe porque a policy notifications_insert_own restringe o insert a user_id = auth.uid(): sem ela, nenhuma Server Action conseguiria notificar o destinatario de um aviso, de uma etapa de tramite ou de um convite. So e chamada de dentro de RPC de transicao ja autorizada, nunca do cliente: quem decide se a notificacao pode existir e a funcao que muda o estado (publicar_aviso, decidir_autorizacao, convite aceito), e nao esta. O titulo carrega o codigo do evento e a borda traduz por lib/status-maps.ts.';

-- 13.3 Relatorio agregado de leitura, sem nome e sem user_id.
create or replace function public.relatorio_leitura_aviso(p_aviso_id uuid)
returns table (
  setor_id     uuid,
  setor_nome   text,
  destinatarios integer,
  confirmados  integer,
  percentual   numeric
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_aviso public.avisos;
begin
  if (select auth.uid()) is null then
    raise exception 'relatorio_leitura_aviso: sem sessao';
  end if;

  select a.* into v_aviso from public.avisos a where a.id = p_aviso_id;
  if not found then
    raise exception 'relatorio_leitura_aviso: aviso % nao encontrado', p_aviso_id;
  end if;

  if not (select private.pertence_ao_espaco(v_aviso.workspace_id)) then
    raise exception 'relatorio_leitura_aviso: fora do espaco do aviso';
  end if;

  -- coalesce duas vezes, e nao por gosto: private.papel_no_grupo devolve nulo
  -- para quem nao e membro do grupo, e nulo nao e falso. Sem o coalesce a
  -- disjuncao inteira virava nulo, "if not null" nunca disparava e o
  -- colaborador sem papel nenhum no setor lia o relatorio inteiro. Mesmo
  -- padrao ja adotado na trilha do documento. Defeito encontrado pela suite
  -- pgTAP do anexo 02b (teste 97).
  if not coalesce(
    v_aviso.autor_id = (select auth.uid())
    or coalesce((select private.papel_no_grupo(v_aviso.grupo_id)), '')
         in ('dono','admin','moderador')
    or (select public.autorizar('mural.ver_relatorio'::public.permissao,
          (select g.setor_id from public.grupos g where g.id = v_aviso.grupo_id)))
  , false) then
    raise exception 'relatorio_leitura_aviso: exige autoria, papel no grupo ou mural.ver_relatorio no setor';
  end if;

  return query
  select
    l.setor_id,
    s.nome,
    count(*)::integer,
    count(l.confirmado_em)::integer,
    round(100.0 * count(l.confirmado_em) / nullif(count(*), 0), 1)
  from public.aviso_leituras l
  left join public.setores s on s.id = l.setor_id
  where l.aviso_id = v_aviso.id
    and l.versao = v_aviso.versao
    and l.obrigatoria
  group by l.setor_id, s.nome
  union all
  select
    null::uuid,
    null::text,
    count(*)::integer,
    count(l.confirmado_em)::integer,
    round(100.0 * count(l.confirmado_em) / nullif(count(*), 0), 1)
  from public.aviso_leituras l
  where l.aviso_id = v_aviso.id
    and l.versao = v_aviso.versao
    and l.obrigatoria;
end;
$$;

comment on function public.relatorio_leitura_aviso(uuid) is
  'Numero, percentual e distribuicao por setor da leitura obrigatoria de um aviso, com a linha de setor_id nulo carregando o total. Nunca devolve user_id. E o caminho do relatorio para o autor, para o dono, admin e moderador do grupo e para quem tem mural.ver_relatorio no setor, depois que a policy aviso_leituras_select_relatorio passou a exigir pessoa.ver_restrito para as linhas nominais: contar quantos leram e minimizacao (LGPD, art. 6, III); listar quem ainda nao leu, com nome, e historico nominal de atraso de quem presta servico voluntario, que aproxima o registro de controle de jornada. A guarda de autorizacao passou a fechar em coalesce: private.papel_no_grupo devolve nulo para quem nao e membro do grupo, a disjuncao inteira virava nulo e o if not nunca disparava, de modo que quem nao entrou no mural nem tinha mural.ver_relatorio no setor lia o relatorio. Defeito encontrado pela suite pgTAP do anexo 02b (teste 97).';

revoke all on function public.publicar_aviso(uuid)                            from public, anon;
revoke all on function public.registrar_notificacoes(text, text, uuid, uuid[]) from public, anon;
revoke all on function public.relatorio_leitura_aviso(uuid)                   from public, anon;

grant execute on function public.publicar_aviso(uuid)                            to authenticated;
grant execute on function public.registrar_notificacoes(text, text, uuid, uuid[]) to authenticated;
grant execute on function public.relatorio_leitura_aviso(uuid)                   to authenticated;


-- ============================================================================
-- 14. GRANTs explicitos
--     A intranet nao repete o grant amplo da Redacao. Por tabela, apenas as
--     operacoes que tem policy. anon nao recebe privilegio em lugar nenhum.
-- ============================================================================

revoke all on table public.grupos         from public, anon;
revoke all on table public.grupo_membros  from public, anon;
revoke all on table public.avisos         from public, anon;
revoke all on table public.aviso_publicos from public, anon;
revoke all on table public.aviso_leituras from public, anon;
revoke all on table public.comentarios    from public, anon;

grant usage on schema public to authenticated;

grant select, insert, update          on table public.grupos         to authenticated;
grant select, insert, update, delete  on table public.grupo_membros  to authenticated;
grant select, insert, update          on table public.avisos         to authenticated;
grant select, insert, update          on table public.aviso_publicos to authenticated;
grant select, insert, update          on table public.aviso_leituras to authenticated;
grant select, insert, update, delete  on table public.comentarios    to authenticated;

-- Tabelas da Redacao estendidas: o privilegio ja existe desde
-- 20260820183726; o grant abaixo e idempotente e documenta o que a intranet
-- passa a usar. Nada e revogado, porque migracao so acrescenta.
grant select, insert, update on table public.notifications to authenticated;
grant select, insert, update on table public.messages      to authenticated;

revoke all on function public.avisos_versionar()            from public, anon;
revoke all on function public.aviso_leituras_nao_regride()  from public, anon;
revoke all on function public.comentarios_um_nivel()        from public, anon;
revoke all on function public.messages_so_lido_em()         from public, anon;
revoke all on function public.avisos_conta_de_servico()     from public, anon;


-- ============================================================================
-- 15. Seed dos oito grupos
--     Um grupo de setor por setor ativo do espaco producao, mais o grupo
--     geral. Sem isso a fase 2 nao sai do zero: nao existe container para
--     nenhum aviso. Idempotente e compativel com os indices unicos parciais
--     grupos_setor_id_idx e grupos_tipo_geral_idx: as guardas not exists
--     repetem a condicao parcial de cada indice, alem do slug unico.
-- ============================================================================

do $$
declare
  v_workspace   uuid;
  v_dono_padrao uuid;
  v_criados     integer;
begin
  select w.id into v_workspace from public.workspaces w where w.slug = 'producao';
  if v_workspace is null then
    raise notice 'Seed de grupos: espaco producao ausente; nada a fazer.';
    return;
  end if;

  -- Dono de reserva, usado apenas enquanto um setor nao tem coordenador com
  -- papel vigente. grupos.dono_id e not null: mural sem dono nomeado nao
  -- existe (Nielsen Norman Group, Step Two).
  select up.user_id into v_dono_padrao
  from public.usuario_papeis up
  where up.papel = 'administrador'
    and up.inicio <= now()
    and (up.fim is null or up.fim > now())
  order by up.criado_em
  limit 1;

  if v_dono_padrao is null then
    select m.user_id into v_dono_padrao
    from public.workspace_members m
    where m.workspace_id = v_workspace
      and m.role = 'admin'
    order by m.id
    limit 1;
  end if;

  -- 15.1 Um grupo de setor por setor ativo.
  insert into public.grupos (
    workspace_id, tipo, setor_id, slug, nome, descricao,
    visibilidade, entrada, status, dono_id, revisao_em
  )
  select
    v_workspace,
    'setor',
    s.id,
    s.slug,
    s.nome,
    format(
      'Mural e espaco de trabalho do setor %s da Cruz Vermelha Brasileira, Filial do Estado do Rio de Janeiro. O texto de Sobre, com finalidade do setor, quem responde por ele e o que se publica aqui, e preenchido pelo dono do mural na primeira revisao trimestral.',
      s.nome
    ),
    'comunidade',
    'por_pedido',
    'active',
    d.dono_id,
    (current_date + interval '90 days')::date
  from public.setores s
  cross join lateral (
    select coalesce(
      (select up.user_id
         from public.usuario_papeis up
        where up.papel = 'coordenador'
          and up.setor_id = s.id
          and up.inicio <= now()
          and (up.fim is null or up.fim > now())
        order by up.inicio desc
        limit 1),
      v_dono_padrao
    ) as dono_id
  ) d
  where s.workspace_id = v_workspace
    and s.ativo
    and d.dono_id is not null
    and not exists (
      select 1 from public.grupos g
      where g.workspace_id = v_workspace and g.tipo = 'setor' and g.setor_id = s.id
    )
    and not exists (
      select 1 from public.grupos g
      where g.workspace_id = v_workspace and g.slug = s.slug
    );

  get diagnostics v_criados = row_count;
  raise notice 'Seed de grupos: % grupo(s) de setor criado(s).', v_criados;

  -- 15.2 O unico grupo geral, sem setor, de entrada aberta.
  insert into public.grupos (
    workspace_id, tipo, setor_id, slug, nome, descricao,
    visibilidade, entrada, status, dono_id, revisao_em
  )
  select
    v_workspace,
    'geral',
    null,
    'geral',
    'Geral',
    'Mural aberto a todas as pessoas da filial, para avisos que nao pertencem a um unico setor. O texto de Sobre e preenchido pelo dono do mural na primeira revisao trimestral.',
    'comunidade',
    'aberta',
    'active',
    v_dono_padrao,
    (current_date + interval '90 days')::date
  where v_dono_padrao is not null
    and not exists (
      select 1 from public.grupos g
      where g.workspace_id = v_workspace and g.tipo = 'geral'
    )
    and not exists (
      select 1 from public.grupos g
      where g.workspace_id = v_workspace and g.slug = 'geral'
    );

  if v_dono_padrao is null then
    raise notice 'Seed de grupos: nenhum dono resolvido (sem coordenador e sem administrador). Rode o seed de novo depois de conceder os papeis.';
  end if;
end $$;



-- ============================================================
-- 20. Biblioteca de documentos, classificação, retenção e templates
-- ============================================================

-- ============================================================
-- Intranet CVB-RJ, parte BIBLIOTECA (Espaco 3)
-- Pastas em arvore com caminho materializado, permissoes com heranca e papeis
-- locais, documentos, versoes com hash SHA-256, tipos documentais, niveis de
-- acesso com hipotese legal, links internos, lixeira, retencao e modelos.
--
-- Origem dos padroes transpostos (desenho, nunca codigo):
--   Papermark  (prisma/schema/document.prisma): Folder com `path` materializado
--              e `parentId`, unico por time; DocumentVersion com `versionNumber`,
--              `isPrimary`, `contentType`, `fileSize`, `storageType` e
--              @@unique([versionNumber, documentId]).
--   Nextcloud Team folders (groupfolders): ACL por subpasta com heranca e
--              quebra explicita (group_folders_acl: fileid, mapping_type,
--              mapping_id, mask, permissions), cota por pasta raiz
--              (group_folders.quota) e lixeira com original_location e
--              deleted_time (group_folders_trash).
--   Plone      (rolemap.xml): papeis locais por pasta, Reader, Contributor,
--              Editor e Reviewer, aqui leitor, contribuidor, editor e revisor.
--   Mayan EDMS (documents/models/document_type_models.py): DocumentType com
--              trash_time_period e delete_time_period, aqui dias_na_lixeira.
--   Paperless-ngx (documents/models.py, ShareLink): slug, expiration e
--              file_version para o link interno de compartilhamento.
--   Papermerge (features/ownership): pasta pertence a um grupo, nunca a uma
--              pessoa; aqui pertence ao setor.
--   SEI        (constantes STA_NIVEL_ACESSO_*, mod-sei-pen): publico, restrito e
--              sigiloso com hipotese legal obrigatoria, credencial nominal para
--              sigiloso, numero de protocolo e regra da minuta.
--   Jorvik     (gestione_file/models.py, DocumentoComitato): categoria do
--              documento por orgao produtor, adaptada ao Estatuto da CVB.
--   Exemplo oficial da Supabase (slack-clone, 20240214114147_auth-hook.sql):
--              permissoes nomeadas lidas por public.autorizar() nas policies.
--   Redacao    (20260820183726_cvrj_editorial_tables.sql e
--              20260820183812_cvrj_editorial_rls.sql): workspace_id em toda
--              tabela, funcoes auxiliares security definer no schema private,
--              policies nomeadas no molde de messages_select_member, trigger de
--              atualizado_em no molde de touch_social_publications.
--
-- Nada e removido da Redacao: esta migracao so acrescenta.
-- Enums (permissao, tipo_ato, nivel_assinatura) e funcoes de base
-- (public.autorizar, public.tocar_atualizado_em, private.exige_aal2,
-- private.pertence_ao_espaco, private.pertence_ao_setor, private.mesmo_setor)
-- vem da parte base. Esta parte chama private.pertence_ao_espaco, e nao
-- private.is_workspace_member da Redacao, porque quem entra por convite ganha
-- vinculo e papel sem nunca ganhar linha em public.workspace_members: com o
-- auxiliar antigo o voluntario nao listaria tipo documental, nao veria
-- hipotese legal e nao conseguiria enviar documento. Pelo mesmo motivo chama
-- private.pertence_ao_setor(setor_id), que recebe setor, e nao
-- private.mesmo_setor(profile_id), que recebe pessoa.
-- ============================================================

-- ------------------------------------------------------------
-- 1. Funcao imutavel do vetor de busca
-- ------------------------------------------------------------

create or replace function public.documento_busca(
  p_titulo     text,
  p_descricao  text,
  p_tags       text[],
  p_metadados  jsonb
) returns tsvector
language sql
immutable
parallel safe
-- search_path vazio pela mesma razao de touch_social_publications na Redacao:
-- funcao com search_path mutavel e vetor de sequestro de nome de objeto.
-- pg_catalog continua implicito, entao os operadores nativos resolvem.
set search_path = ''
as $$
  select to_tsvector(
    'pg_catalog.portuguese'::regconfig,
    coalesce(p_titulo, '') || ' ' ||
    coalesce(p_descricao, '') || ' ' ||
    coalesce(array_to_string(p_tags, ' '), '') || ' ' ||
    coalesce(
      (select string_agg(e.value, ' ')
         from jsonb_each_text(coalesce(p_metadados, '{}'::jsonb)) as e),
      ''
    )
  );
$$;

comment on function public.documento_busca(text, text, text[], jsonb) is
  'Monta o tsvector em portugues de titulo, descricao, tags e valores textuais dos metadados. Existe como funcao porque array_to_string e declarada estavel e nao pode entrar direto em coluna gerada; para text[] a saida e deterministica, por isso a funcao e declarada imutavel. Padrao de busca por tsvector indicado na secao 5.4 da recomendacao de base.';

revoke all on function public.documento_busca(text, text, text[], jsonb) from public, anon;
grant execute on function public.documento_busca(text, text, text[], jsonb) to authenticated;

-- ------------------------------------------------------------
-- 2. Vocabulario controlado de hipoteses legais (SEI)
-- ------------------------------------------------------------

create table if not exists public.hipoteses_legais (
  id                   uuid primary key default gen_random_uuid(),
  workspace_id         uuid not null references public.workspaces (id) on delete cascade,
  codigo               text not null,
  nome                 text not null,
  descricao            text,
  exige_dado_sensivel  boolean not null default false,
  ativo                boolean not null default true,
  criado_em            timestamptz not null default now(),
  constraint hipoteses_legais_codigo_unico unique (workspace_id, codigo),
  constraint hipoteses_legais_codigo_formato
    check (codigo ~ '^[a-z0-9]+(_[a-z0-9]+)*$')
);

comment on table public.hipoteses_legais is
  'Vocabulario controlado das hipoteses legais de restricao e sigilo, no molde do SEI, com seed e edicao pelo administrador. Sem ela cada pessoa escreveria um texto livre diferente em documentos.hipotese_legal.';
comment on column public.hipoteses_legais.codigo is
  'Codigo estavel usado como chave de negocio por documentos.hipotese_legal, por exemplo dados_sensiveis_lgpd_art11. A chave primaria continua sendo uuid, pela convencao de tipos da casa.';
comment on column public.hipoteses_legais.exige_dado_sensivel is
  'Marca a hipotese do art. 11 da LGPD, para a qual o legitimo interesse nao se aplica.';

-- ------------------------------------------------------------
-- 3. Arvore de pastas (Papermark Folder, Team folders, Papermerge)
-- ------------------------------------------------------------

create table if not exists public.pastas (
  id                   uuid primary key default gen_random_uuid(),
  workspace_id         uuid not null references public.workspaces (id) on delete cascade,
  parent_id            uuid references public.pastas (id) on delete restrict,
  nome                 text not null,
  slug                 text not null,
  path                 text not null,
  profundidade         smallint not null default 1,
  setor_id             uuid references public.setores (id) on delete restrict,
  raiz                 boolean not null default false,
  herda_permissoes     boolean not null default true,
  cota_bytes           bigint,
  nivel_acesso_maximo  text not null default 'publico',
  descricao            text,
  criado_por           uuid references public.profiles (id) on delete set null,
  criado_em            timestamptz not null default now(),
  atualizado_em        timestamptz not null default now(),
  constraint pastas_workspace_path_unico unique (workspace_id, path),
  constraint pastas_nome_tamanho check (char_length(nome) between 1 and 120),
  constraint pastas_slug_formato check (slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
  constraint pastas_path_formato check (path ~ '^/[a-z0-9/-]+$'),
  constraint pastas_profundidade_maxima check (profundidade between 1 and 6),
  constraint pastas_nivel_acesso_maximo_valido
    check (nivel_acesso_maximo in ('publico', 'restrito', 'sigiloso')),
  constraint pastas_cota_positiva check (cota_bytes is null or cota_bytes > 0),
  -- A arvore de seed tem tres niveis (/setores, /setores/<setor> e
  -- /setores/<setor>/procedimentos), entao a marca de raiz vale ate a
  -- profundidade 3. A constraint anterior parava em 2 e reprovava as 21
  -- subpastas de setor criadas pelo proprio seed, abortando a migracao.
  constraint pastas_raiz_ate_profundidade_3
    check (not raiz or profundidade <= 3)
);

comment on table public.pastas is
  'Arvore de pastas com caminho materializado unico por espaco, dona por setor e nunca por pessoa. Caminho materializado e parent_id transpostos do model Folder do Papermark (prisma/schema/document.prisma, path sempre iniciando com barra e unico por time); cota da subarvore e quebra de heranca transpostas de group_folders.quota e group_folders_acl do Nextcloud Team folders; dono por setor em vez de pessoa transposto de ownerships do Papermerge, o que evita pasta orfa quando o voluntario sai.';
comment on column public.pastas.path is
  'Caminho materializado, por exemplo /setores/saude/procedimentos. Recalculado nos descendentes por public.pastas_recalcular_subarvore ao mover ou renomear.';
comment on column public.pastas.setor_id is
  'Setor dono da pasta. Nunca uma pessoa, para que a saida de voluntarios e coordenadores nao deixe pasta orfa.';
comment on column public.pastas.raiz is
  'Pasta criada por seed. Nao pode ser movida, renomeada nem apagada. Vale ate a profundidade 3, que e onde termina a arvore do seed.';
comment on column public.pastas.herda_permissoes is
  'Falso corta a heranca e obriga regras proprias, a quebra explicita do Nextcloud Team folders e do Alfresco.';
comment on column public.pastas.nivel_acesso_maximo is
  'Maior nivel de acesso entre os documentos contidos, mantido por trigger, com piso restrito nas pastas de setor marcado como restrito_por_padrao. Regra do conjunto do SEI, so para exibicao.';

-- ------------------------------------------------------------
-- 4. Tipos documentais e temporalidade (Mayan, Jorvik, e-ARQ)
-- ------------------------------------------------------------

create table if not exists public.tipos_documentais (
  id                            uuid primary key default gen_random_uuid(),
  workspace_id                  uuid not null references public.workspaces (id) on delete cascade,
  tipo_ato                      public.tipo_ato not null,
  nome                          text not null,
  orgao                         text not null,
  metadados_obrigatorios        jsonb not null default '{}',
  nivel_acesso_padrao           text not null default 'restrito',
  contem_dados_pessoais         boolean not null default false,
  base_legal                    text not null,
  prazo_guarda_anos             smallint,
  guarda_permanente             boolean not null default false,
  prazo_pendente_decisao        boolean not null default true,
  prazo_envio_dias              smallint,
  destinatarios_automaticos     text[] not null default '{}',
  dias_na_lixeira               smallint not null default 30,
  pode_eliminar_antes_do_prazo  boolean not null default true,
  ativo                         boolean not null default true,
  criado_em                     timestamptz not null default now(),
  atualizado_em                 timestamptz not null default now(),
  constraint tipos_documentais_tipo_ato_unico unique (workspace_id, tipo_ato),
  constraint tipos_documentais_orgao_valido
    check (orgao in ('assembleia', 'junta_de_governo', 'diretoria',
                     'coordenacao', 'revisao_de_contas', 'pessoa')),
  constraint tipos_documentais_nivel_padrao_valido
    check (nivel_acesso_padrao in ('publico', 'restrito', 'sigiloso')),
  -- Os cinco primeiros valores de tipo_ato sao tramites leves sem arquivo e
  -- nao produzem documento; so os demais entram no catalogo documental.
  constraint tipos_documentais_tipo_ato_produz_documento
    check (tipo_ato not in ('uso_imagem', 'participacao_acao', 'ressarcimento',
                            'acesso_pasta', 'reativacao_vinculo')),
  -- Tres estados legitimos de temporalidade: guarda permanente, prazo ainda
  -- pendente de decisao da Diretoria, ou prazo fixado em anos.
  constraint tipos_documentais_guarda_coerente
    check (guarda_permanente
           or prazo_pendente_decisao
           or prazo_guarda_anos is not null),
  constraint tipos_documentais_prazos_positivos
    check ((prazo_guarda_anos is null or prazo_guarda_anos > 0)
       and (prazo_envio_dias is null or prazo_envio_dias > 0)
       and dias_na_lixeira >= 0),
  constraint tipos_documentais_publico_sem_dado_pessoal
    check (not (contem_dados_pessoais and nivel_acesso_padrao = 'publico'))
);

comment on table public.tipos_documentais is
  'Catalogo dos tipos documentais com orgao produtor, metadados obrigatorios, nivel de acesso padrao, base legal, prazo de guarda, prazo de envio aos destinatarios e dias na lixeira. E a tabela de temporalidade do e-ARQ Brasil 2 (Resolucao CONARQ 50/2022). Prazo de lixeira transposto de trash_time_period e delete_time_period do DocumentType do Mayan EDMS; taxonomia por orgao transposta do DocumentoComitato do Jorvik e adaptada ao Estatuto da CVB. Nao guarda nivel de assinatura, que e competencia de politicas_assinatura.';
comment on column public.tipos_documentais.metadados_obrigatorios is
  'Esquema dos metadados exigidos. Aceita a forma {"required": ["campo"]} do JSON Schema ou o atalho {"campos": ["campo"]}; o trigger documentos_valida_metadados recusa documento sem esses campos. O nome data_referencia e conferido na coluna documentos.data_referencia, e nao dentro do jsonb, para que o dado nao seja digitado duas vezes.';
comment on column public.tipos_documentais.prazo_pendente_decisao is
  'Verdadeiro enquanto a Diretoria nao fixar o prazo de guarda do tipo. Nesse estado documentos_valida_metadados deixa retencao_ate nula e documentos_bloqueia_eliminacao nao bloqueia por prazo. Existe porque o seed anterior inventava cinco e dez anos onde a propria decisao D27 diz que o prazo nao esta fixado, e um prazo inventado trava por anos o direito de eliminacao do titular sobre termo de adesao, termo de desligamento e autorizacao de imagem. So nascem com prazo fixado prestacao_contas, pelo art. 68 do MROSC, e as tres atas, por guarda permanente do Estatuto.';
comment on column public.tipos_documentais.prazo_envio_dias is
  'Prazo para enviar aos destinatarios apos a versao primaria. Vale 15 para ata_junta, pelo art. 33, paragrafo 1, do Estatuto da CVB, estendido as Juntas Estaduais pelo paragrafo 3.';
comment on column public.tipos_documentais.pode_eliminar_antes_do_prazo is
  'Falso bloqueia eliminacao ate retencao_ate. Vale para prestacao de contas, dez anos pelo art. 68 do MROSC, e para os tipos de guarda permanente do Estatuto.';

-- ------------------------------------------------------------
-- 5. Documentos (identificador arquivistico unico do e-ARQ)
-- ------------------------------------------------------------

create table if not exists public.documentos (
  id                           uuid primary key default gen_random_uuid(),
  workspace_id                 uuid not null references public.workspaces (id) on delete cascade,
  pasta_id                     uuid not null references public.pastas (id) on delete restrict,
  tipo_documental_id           uuid not null references public.tipos_documentais (id) on delete restrict,
  titulo                       text not null,
  descricao                    text,
  tags                         text[] not null default '{}',
  metadados                    jsonb not null default '{}',
  numero_registro              text,
  nivel_acesso                 text not null default 'restrito',
  hipotese_legal               text,
  setor_id                     uuid references public.setores (id) on delete restrict,
  status                       text not null default 'draft',
  vigencia_inicio              date,
  vigencia_fim                 date,
  revisao_em                   date,
  data_referencia              date,
  retencao_ate                 date,
  nivel_assinatura_registrado  public.nivel_assinatura not null default 'nenhuma',
  lixeira_em                   timestamptz,
  pasta_original_id            uuid references public.pastas (id) on delete set null,
  eliminado_em                 timestamptz,
  busca                        tsvector generated always as
    (public.documento_busca(titulo, descricao, tags, metadados)) stored,
  criado_por                   uuid references public.profiles (id) on delete set null,
  criado_em                    timestamptz not null default now(),
  atualizado_em                timestamptz not null default now(),
  constraint documentos_titulo_tamanho check (char_length(titulo) between 1 and 240),
  constraint documentos_nivel_acesso_valido
    check (nivel_acesso in ('publico', 'restrito', 'sigiloso')),
  constraint documentos_status_valido
    check (status in ('draft', 'current', 'archived', 'trashed', 'erased')),
  constraint documentos_hipotese_obrigatoria
    check (nivel_acesso = 'publico' or hipotese_legal is not null),
  constraint documentos_vigencia_coerente
    check (vigencia_fim is null or vigencia_inicio is null or vigencia_fim >= vigencia_inicio),
  constraint documentos_lixeira_coerente
    check ((status = 'trashed') = (lixeira_em is not null) or status = 'erased'),
  constraint documentos_eliminado_coerente
    check ((status = 'erased') = (eliminado_em is not null)),
  constraint documentos_hipotese_do_espaco
    foreign key (workspace_id, hipotese_legal)
    references public.hipoteses_legais (workspace_id, codigo)
    on update cascade
);

comment on table public.documentos is
  'Registro logico do documento e identificador arquivistico unico do e-ARQ Brasil 2: tipo, metadados validados contra o esquema do tipo, numero de protocolo, nivel de acesso com hipotese legal, setor dono, vigencia, revisao, data de referencia e retencao calculada, nivel de assinatura aplicado, lixeira com pasta original e eliminacao. Separacao entre documento, arquivo e versao transposta do Mayan EDMS; folderId e ownerId transpostos do Document do Papermark; niveis de acesso com hipotese legal e numero de protocolo transpostos do SEI. Nunca aceita delete: eliminar e update por public.eliminar_documento, que apaga o binario e mantem o hash.';
comment on column public.documentos.nivel_acesso is
  'Vocabulario do SEI. publico significa qualquer membro autenticado que alcance a pasta, nunca publicacao externa; restrito exige hipotese legal; sigiloso exige hipotese legal, credencial nominal e sessao com aal2. No envio o valor e derivado de tipos_documentais.nivel_acesso_padrao e elevado a restrito quando a pasta pertence a setor restrito_por_padrao; alterar depois e ato de revisor com aal2.';
comment on column public.documentos.hipotese_legal is
  'Codigo de hipoteses_legais, obrigatorio quando nivel_acesso nao e publico. Vocabulario controlado do SEI. No envio e derivado do tipo documental quando vem nulo.';
comment on column public.documentos.numero_registro is
  'Numero de protocolo por espaco e por ano, gerado pelo banco para oficio, ata, parecer e prestacao de contas. Padrao de protocolo do SEI.';
comment on column public.documentos.data_referencia is
  'Data do fato que o documento registra, e nao a data do envio. E dela que documentos_valida_metadados calcula retencao_ate, por isso o significado e fixado por tipo documental: para termo_adesao e termo_desligamento recebe a data de fim do vinculo, ficando nula enquanto o vinculo vigorar, o que mantem retencao_ate nula e bloqueia a eliminacao por rotina; para ata_junta, ata_assembleia, ata_diretoria, oficio, parecer e prestacao_contas recebe a data do ato; para certificado recebe a data de conclusao. Os tipos que a exigem trazem data_referencia na lista de metadados obrigatorios.';
comment on column public.documentos.retencao_ate is
  'Data calculada por trigger: data_referencia mais tipos_documentais.prazo_guarda_anos. Nula para guarda permanente e enquanto o tipo estiver com prazo_pendente_decisao.';
comment on column public.documentos.pasta_original_id is
  'Pasta de origem, guardada ao enviar para a lixeira para permitir a restauracao. Transposta de original_location de group_folders_trash do Nextcloud Team folders.';
comment on column public.documentos.busca is
  'Coluna gerada com tsvector em portugues de titulo, descricao, tags e metadados textuais, indexada por GIN.';

-- ------------------------------------------------------------
-- 6. Versoes de documento (Papermark DocumentVersion, Mayan DocumentFile)
-- ------------------------------------------------------------

create table if not exists public.documento_versoes (
  id                       uuid primary key default gen_random_uuid(),
  workspace_id             uuid not null references public.workspaces (id) on delete cascade,
  documento_id             uuid not null references public.documentos (id) on delete restrict,
  numero                   integer not null default 0,
  is_primary               boolean not null default false,
  storage_backend          text not null default 'vercel_blob',
  storage_path             text,
  content_type             text not null,
  size_bytes               bigint not null default 0,
  hash_sha256              text not null,
  origem                   text not null default 'upload',
  motivo                   text,
  resultado_validador_iti  text,
  texto_extraido           text,
  extracao_status          text not null default 'pending',
  extracao_tentativas      smallint not null default 0,
  extracao_erro            text,
  hash_reconferido_em      timestamptz,
  hash_reconferencia_ok    boolean,
  busca                    tsvector generated always as
    (to_tsvector('portuguese', coalesce(texto_extraido, ''))) stored,
  enviado_por              uuid references public.profiles (id) on delete set null,
  eliminada_em             timestamptz,
  criado_em                timestamptz not null default now(),
  constraint documento_versoes_numero_unico unique (documento_id, numero),
  constraint documento_versoes_numero_positivo check (numero >= 0),
  constraint documento_versoes_backend_valido
    check (storage_backend in ('vercel_blob', 'supabase_storage', 'gdrive')),
  constraint documento_versoes_origem_valida
    check (origem in ('upload', 'gerado', 'assinado_govbr', 'migrado')),
  constraint documento_versoes_extracao_valida
    check (extracao_status in ('pending', 'ok', 'no_text', 'failed', 'too_large')),
  constraint documento_versoes_extracao_tentativas_positivas
    check (extracao_tentativas >= 0),
  constraint documento_versoes_validador_valido
    check (resultado_validador_iti is null
           or resultado_validador_iti in ('aprovado', 'invalido', 'indeterminado',
                                          'assinatura_desconhecida')),
  constraint documento_versoes_hash_hex
    check (hash_sha256 ~ '^[0-9a-f]{64}$'),
  constraint documento_versoes_motivo_tamanho
    check (motivo is null or char_length(motivo) <= 200),
  constraint documento_versoes_tamanho_positivo check (size_bytes >= 0)
);

comment on table public.documento_versoes is
  'Cada arquivo binario de um documento, com numero sequencial, exatamente uma versao primaria por indice unico parcial, hash SHA-256 calculado no navegador e recalculado no servidor, backend e caminho de armazenamento, origem, motivo, resultado do validador do ITI e texto extraido. versionNumber, isPrimary, contentType, fileSize e storageType transpostos do DocumentVersion do Papermark, inclusive a unicidade de versao por documento; checksum por arquivo transposto do DocumentFile do Mayan EDMS; hash calculado duas vezes e preservado apos a eliminacao vem da secao 6 da pesquisa de rastreabilidade. A versao primaria nunca e editada: corrigir e subir nova versao.';
comment on column public.documento_versoes.hash_sha256 is
  'SHA-256 em 64 hexadecimais, calculado no navegador com WebCrypto e recalculado no servidor ao registrar. Divergencia recusa o registro. Permanece apos a eliminacao, quando storage_path e texto_extraido sao anulados.';
comment on column public.documento_versoes.storage_backend is
  'Existe desde a primeira migracao para que a decisao D12 (Vercel Blob, Supabase Storage ou indice do Google Drive) nao exija mudanca de schema. Transposto de storageType do Papermark.';
comment on column public.documento_versoes.resultado_validador_iti is
  'As quatro palavras que validar.iti.gov.br devolve, gravadas pela parte de autorizacao para versoes assinadas.';
comment on column public.documento_versoes.extracao_status is
  'Estado da extracao de texto por /api/biblioteca/extrair-texto. no_text e o PDF digitalizado sem camada de texto, buscavel so por metadados; OCR fica fora desta rodada. Regra de operacao: versao nenhuma pode ficar em pending para sempre. O job horario de reprocessamento consome a fila do indice parcial de extracao_status e criado_em, incrementa extracao_tentativas e, depois de tres tentativas, grava failed com o motivo em extracao_erro; a tela de operacao conta quantas versoes estao em pending e quantas em failed. Sem isso a busca por conteudo, que e o argumento da fase 3 contra o indice do Drive, falha em silencio.';
comment on column public.documento_versoes.extracao_tentativas is
  'Quantas vezes o job de extracao ja tentou esta versao. Na terceira falha o job para de tentar e grava failed.';
comment on column public.documento_versoes.extracao_erro is
  'Motivo tecnico da ultima falha de extracao, mostrado na tela de operacao. Nunca guarda trecho do documento.';
comment on column public.documento_versoes.hash_reconferido_em is
  'Momento da ultima reconferencia do hash_sha256 contra o arquivo no destino, feita pelo job diario que consome o indice parcial desta coluna. Existe porque o backend gdrive do check de storage_backend deixa o binario fora do Postgres, onde qualquer pessoa com acesso ao drive substitui o arquivo sem passar pela intranet, e a unica defesa e recalcular o hash contra o destino e abrir incidente em lgpd.incidentes quando divergir. A reconferencia vale para os tres backends, nao so para o gdrive; a intranet continua sendo a unica porta de leitura, por /api/biblioteca/arquivo/[versaoId]; e a adocao do gdrive depende do desenho tecnico aprovado junto de D12.';
comment on column public.documento_versoes.hash_reconferencia_ok is
  'Resultado da ultima reconferencia. Falso e incidente: o arquivo no destino deixou de bater com o hash registrado no envio.';

-- ------------------------------------------------------------
-- 7. Permissoes por pasta e por documento (Team folders + Plone)
-- ------------------------------------------------------------

create table if not exists public.pasta_permissoes (
  id                  uuid primary key default gen_random_uuid(),
  workspace_id        uuid not null references public.workspaces (id) on delete cascade,
  pasta_id            uuid not null references public.pastas (id) on delete cascade,
  documento_id        uuid references public.documentos (id) on delete cascade,
  sujeito_tipo        text not null,
  sujeito_papel       text references public.papeis (slug) on update cascade,
  sujeito_setor_id    uuid references public.setores (id) on delete cascade,
  sujeito_usuario_id  uuid references public.profiles (id) on delete cascade,
  papel_local         text not null,
  efeito              text not null default 'permitir',
  expira_em           timestamptz,
  concedido_por       uuid references public.profiles (id) on delete set null,
  motivo              text,
  criado_em           timestamptz not null default now(),
  constraint pasta_permissoes_sujeito_tipo_valido
    check (sujeito_tipo in ('papel', 'setor', 'usuario')),
  constraint pasta_permissoes_papel_local_valido
    check (papel_local in ('leitor', 'contribuidor', 'editor', 'revisor')),
  constraint pasta_permissoes_efeito_valido
    check (efeito in ('permitir', 'negar')),
  -- O sujeito deixou de ser texto polimorfico: sao tres colunas e exatamente
  -- uma preenchida, coerente com sujeito_tipo.
  constraint pasta_permissoes_sujeito_unico
    check (
      (sujeito_tipo = 'papel'   and sujeito_papel is not null
        and sujeito_setor_id is null and sujeito_usuario_id is null)
      or (sujeito_tipo = 'setor'   and sujeito_setor_id is not null
        and sujeito_papel is null and sujeito_usuario_id is null)
      or (sujeito_tipo = 'usuario' and sujeito_usuario_id is not null
        and sujeito_papel is null and sujeito_setor_id is null)
    ),
  -- Credencial nominal de documento sigiloso: sempre com motivo escrito.
  constraint pasta_permissoes_credencial_com_motivo
    check (documento_id is null or sujeito_tipo <> 'usuario'
           or (motivo is not null and char_length(motivo) >= 5))
);

comment on table public.pasta_permissoes is
  'Regras de permissao sobre pasta ou sobre documento, para um papel institucional, um setor ou uma pessoa, com papel local, efeito permitir ou negar, expiracao e motivo. Tambem e onde mora a credencial nominal de documento sigiloso. Heranca pela cadeia de ancestrais, quebra explicita e o par permitir/negar transpostos de group_folders_acl do Nextcloud Team folders (fileid, mapping_type, mapping_id, mask, permissions) e de lib/ACL/Rule.php; papeis locais leitor, contribuidor, editor e revisor transpostos do rolemap.xml do Plone; credencial nominal para sigiloso transposta do SEI; permissao por item alem da pasta transposta de canView e canDownload do Papermark. Revogar e update de expira_em, nunca delete.';
comment on column public.pasta_permissoes.documento_id is
  'Quando preenchido, a regra e excecao para esse documento e vence a heranca da pasta. Unica porta do nivel sigiloso quando sujeito_tipo e usuario.';
comment on column public.pasta_permissoes.efeito is
  'negar vence permitir no mesmo nivel; o nivel mais proximo do alvo vence os ancestrais. Semantica dos dois bitmaps mask e permissions do Team folders.';
comment on column public.pasta_permissoes.expira_em is
  'Permissao temporaria. Revogar uma regra vigente e gravar expira_em = now(), porque nada e apagado nesta base.';

-- ------------------------------------------------------------
-- 8. Links internos de compartilhamento (Paperless-ngx ShareLink)
-- ------------------------------------------------------------

create table if not exists public.documento_links (
  id                uuid primary key default gen_random_uuid(),
  workspace_id      uuid not null references public.workspaces (id) on delete cascade,
  documento_id      uuid not null references public.documentos (id) on delete cascade,
  versao_id         uuid references public.documento_versoes (id) on delete set null,
  slug              text not null,
  permite_download  boolean not null default false,
  expira_em         timestamptz not null,
  revogado_em       timestamptz,
  acessos           integer not null default 0,
  ultimo_acesso_em  timestamptz,
  criado_por        uuid references public.profiles (id) on delete set null,
  criado_em         timestamptz not null default now(),
  constraint documento_links_slug_unico unique (slug),
  constraint documento_links_slug_formato check (slug ~ '^[a-z2-7]{26}$'),
  constraint documento_links_prazo_maximo
    check (expira_em > criado_em and expira_em <= criado_em + interval '30 days'),
  constraint documento_links_acessos_positivos check (acessos >= 0)
);

comment on table public.documento_links is
  'Link interno de compartilhamento de uma versao, com slug aleatorio de 128 bits em base32, expiracao obrigatoria de no maximo 30 dias, permissao de download, revogacao e contagem de acessos. slug, expiration e file_version transpostos do ShareLink do Paperless-ngx (src/documents/models.py); codigo de alta entropia sem enumeracao vem da secao 6 da pesquisa de rastreabilidade. Abrir exige sessao: e como o mural aponta um procedimento sem duplicar o arquivo. Nunca e emitido para documento sigiloso.';
comment on column public.documento_links.versao_id is
  'Versao fixada. Nulo aponta sempre para a versao primaria vigente.';
comment on column public.documento_links.permite_download is
  'Falso entrega so a leitura na tela: public.resolver_link_documento devolve storage_path nulo, e sem caminho a rota /api/biblioteca/arquivo/[versaoId] nao entrega bytes.';
comment on column public.documento_links.slug is
  '26 caracteres em base32 sem caracteres ambiguos, 128 bits de entropia, no molde do token de /validar/[token] do Curso.';

-- ------------------------------------------------------------
-- 9. Modelos de documento
-- ------------------------------------------------------------

create table if not exists public.modelos_documento (
  id                    uuid primary key default gen_random_uuid(),
  workspace_id          uuid not null references public.workspaces (id) on delete cascade,
  slug                  text not null,
  nome                  text not null,
  tipo_documental_id    uuid not null references public.tipos_documentais (id) on delete restrict,
  versao                integer not null default 1,
  corpo                 text not null,
  variaveis             jsonb not null default '{}',
  fonte                 text,
  status                text not null default 'draft',
  revisado_por          uuid references public.profiles (id) on delete set null,
  revisado_em           timestamptz,
  parecer               text,
  pasta_destino_regra   text not null default 'pessoa',
  criado_por            uuid references public.profiles (id) on delete set null,
  criado_em             timestamptz not null default now(),
  atualizado_em         timestamptz not null default now(),
  constraint modelos_documento_slug_unico unique (workspace_id, slug),
  constraint modelos_documento_slug_formato
    check (slug ~ '^[a-z0-9]+(_[a-z0-9]+)*$'),
  constraint modelos_documento_versao_positiva check (versao >= 1),
  constraint modelos_documento_status_valido
    check (status in ('draft', 'legal_review', 'approved', 'obsolete')),
  constraint modelos_documento_destino_valido
    check (pasta_destino_regra in ('pessoa', 'setor', 'institucional')),
  -- Regra dura: so modelo aprovado gera documento valido, e aprovar exige
  -- parecer juridico com autor e data.
  constraint modelos_documento_aprovado_com_parecer
    check (status <> 'approved'
           or (revisado_por is not null and revisado_em is not null))
);

comment on table public.modelos_documento is
  'Modelos institucionais em Markdown com marcadores de perfil, setor, instituicao e data, esquema das variaveis extras, fonte do texto, versao e estado de revisao juridica. Conteudo vem dos modelos da Abong na Plataforma Conjunta sobre o formulario nacional CVB-CADVOL-FORM01; PDF gerado e espelhado em storage proprio no molde de Agreement e AgreementResponse do Papermark; ata em PDF com hash no molde do DRK Rundlaufbeschluesse; a regra de minuta do SEI vira o estado do modelo. So status approved gera documento valido; os demais geram previa com marca dagua e nao criam versao.';
comment on column public.modelos_documento.corpo is
  'Markdown com marcadores pessoa, setor, instituicao e data mais as variaveis do esquema. O emblema so entra no PDF em uso indicativo com o nome da Sociedade, depois da diretriz do Orgao Central; ate la o cabecalho usa so o nome por extenso.';
comment on column public.modelos_documento.pasta_destino_regra is
  'Onde o documento gerado nasce: pasta da pessoa, pasta do setor ou pasta institucional.';

-- ------------------------------------------------------------
-- 10. Ligacao com a Biblioteca editorial da Redacao (public.files)
--     Migracao so acrescenta: nenhuma coluna da Redacao sai.
-- ------------------------------------------------------------

alter table public.files
  add column if not exists documento_id uuid references public.documentos (id) on delete set null;
alter table public.files
  add column if not exists autorizacao_documento_id uuid references public.documentos (id) on delete set null;

comment on column public.files.documento_id is
  'Documento institucional de destino da acao unica e auditada migrarArquivosInstitucionais. A linha de files passa a status migrated e o storage_path e reaproveitado sem copiar bytes. files.status nao tem check na Redacao, entao o valor novo entra sem alterar constraint.';
comment on column public.files.autorizacao_documento_id is
  'Documento do tipo autorizacao_imagem que cobre esta midia. Revogacao na intranet leva files.authorization_status a internal, e o publicador da Redacao continua conferindo o mesmo valor no servidor, sem alteracao de codigo do lado dele.';

create index if not exists files_documento_id_idx
  on public.files (documento_id) where documento_id is not null;
create index if not exists files_autorizacao_documento_id_idx
  on public.files (autorizacao_documento_id) where autorizacao_documento_id is not null;

-- ------------------------------------------------------------
-- 11. Indices: navegacao, metadados, vencimentos e texto
-- ------------------------------------------------------------

create index if not exists pastas_workspace_path_idx
  on public.pastas (workspace_id, path);
create index if not exists pastas_parent_id_idx
  on public.pastas (parent_id);
create index if not exists pastas_workspace_setor_id_idx
  on public.pastas (workspace_id, setor_id);

create index if not exists tipos_documentais_workspace_ativo_idx
  on public.tipos_documentais (workspace_id, ativo);

create index if not exists hipoteses_legais_workspace_ativo_idx
  on public.hipoteses_legais (workspace_id, ativo);

create index if not exists documentos_pasta_id_status_idx
  on public.documentos (pasta_id, status);
create index if not exists documentos_workspace_tipo_documental_id_idx
  on public.documentos (workspace_id, tipo_documental_id);
create index if not exists documentos_workspace_setor_id_status_idx
  on public.documentos (workspace_id, setor_id, status);
create index if not exists documentos_workspace_nivel_acesso_idx
  on public.documentos (workspace_id, nivel_acesso);
create index if not exists documentos_workspace_retencao_ate_idx
  on public.documentos (workspace_id, retencao_ate)
  where retencao_ate is not null and eliminado_em is null;
create index if not exists documentos_workspace_revisao_em_idx
  on public.documentos (workspace_id, revisao_em)
  where revisao_em is not null;
create index if not exists documentos_workspace_lixeira_em_idx
  on public.documentos (workspace_id, lixeira_em)
  where lixeira_em is not null;
create unique index if not exists documentos_workspace_numero_registro_idx
  on public.documentos (workspace_id, numero_registro)
  where numero_registro is not null;
-- Busca por texto com dicionario portugues e busca por metadados em jsonb.
create index if not exists documentos_busca_idx
  on public.documentos using gin (busca);
create index if not exists documentos_metadados_idx
  on public.documentos using gin (metadados jsonb_path_ops);
create index if not exists documentos_tags_idx
  on public.documentos using gin (tags);

create unique index if not exists documento_versoes_documento_id_primaria_idx
  on public.documento_versoes (documento_id) where is_primary;
create index if not exists documento_versoes_documento_id_numero_idx
  on public.documento_versoes (documento_id, numero desc);
create index if not exists documento_versoes_hash_sha256_idx
  on public.documento_versoes (hash_sha256);
-- Fila do job horario de reprocessamento de extracao: pendentes primeiro, na
-- ordem de chegada, e as falhas para a contagem da tela de operacao.
create index if not exists documento_versoes_extracao_status_criado_em_idx
  on public.documento_versoes (extracao_status, criado_em)
  where extracao_status in ('pending', 'failed');
-- Fila do job diario de reconferencia de hash: nunca reconferida primeiro,
-- depois a mais antiga; so versoes com binario vivo.
create index if not exists documento_versoes_hash_reconferido_em_idx
  on public.documento_versoes (hash_reconferido_em nulls first, criado_em)
  where eliminada_em is null and storage_path is not null;
create index if not exists documento_versoes_busca_idx
  on public.documento_versoes using gin (busca);

create unique index if not exists pasta_permissoes_alvo_sujeito_idx
  on public.pasta_permissoes (
    pasta_id,
    coalesce(documento_id, '00000000-0000-0000-0000-000000000000'::uuid),
    sujeito_tipo,
    coalesce(sujeito_papel, ''),
    coalesce(sujeito_setor_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(sujeito_usuario_id, '00000000-0000-0000-0000-000000000000'::uuid),
    papel_local
  );
create index if not exists pasta_permissoes_sujeito_usuario_id_idx
  on public.pasta_permissoes (sujeito_usuario_id) where sujeito_usuario_id is not null;
create index if not exists pasta_permissoes_sujeito_setor_id_idx
  on public.pasta_permissoes (sujeito_setor_id) where sujeito_setor_id is not null;
create index if not exists pasta_permissoes_documento_id_idx
  on public.pasta_permissoes (documento_id) where documento_id is not null;

create index if not exists documento_links_documento_id_idx
  on public.documento_links (documento_id);
create index if not exists documento_links_criado_por_idx
  on public.documento_links (criado_por);

create index if not exists modelos_documento_workspace_status_idx
  on public.modelos_documento (workspace_id, status);
create index if not exists modelos_documento_tipo_documental_id_idx
  on public.modelos_documento (tipo_documental_id);

-- ------------------------------------------------------------
-- 12. Auxiliares de RLS no schema private
--     Mesmo padrao das funcoes da Redacao em 20260820183812:
--     security definer, stable, set search_path vazio, cada uma respondendo
--     apenas sobre auth.uid().
-- ------------------------------------------------------------

create or replace function private.permissao_no_setor(
  p_permissao public.permissao,
  p_setor_id  uuid
) returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select (select public.autorizar('operacao.administrar'::public.permissao, null::uuid))
      or (
        p_setor_id is not null
        and exists (
          select 1
          from public.usuario_papeis up
          join public.papel_permissoes pp on pp.papel = up.papel
          where up.user_id = (select auth.uid())
            and up.setor_id = p_setor_id
            and up.inicio <= now()
            and (up.fim is null or up.fim > now())
            and pp.permissao = p_permissao
        )
      );
$$;

comment on function private.permissao_no_setor(public.permissao, uuid) is
  'Verdadeiro quando auth.uid() tem a permissao pedida por um papel de usuario_papeis atribuido exatamente a este setor, vigente na data de hoje. Papel de escopo global e ignorado de proposito: a unica excecao e quem tem operacao.administrar. Existe porque private.papel_na_pasta dava revisor a qualquer papel global com documento.permissionar, o que fazia dessa pessoa revisora de todas as pastas de todos os setores e contrariava a matriz de papeis e a regra de credencial nominal do nivel sigiloso.';

create or replace function private.tem_credencial_nominal(p_documento_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.pasta_permissoes r
    where r.documento_id = p_documento_id
      and r.sujeito_tipo = 'usuario'
      and r.sujeito_usuario_id = (select auth.uid())
      and r.efeito = 'permitir'
      and (r.expira_em is null or r.expira_em > now())
  );
$$;

comment on function private.tem_credencial_nominal(uuid) is
  'Verdadeiro quando existe credencial nominal vigente de auth.uid() sobre o documento, isto e, linha de pasta_permissoes com documento_id, sujeito_tipo usuario, efeito permitir e sem expiracao vencida. E a unica porta do nivel sigiloso, regra do SEI, e tambem quem enxerga minuta de outra pessoa.';

create or replace function private.documento_autor(p_documento_id uuid)
returns uuid
language sql
security definer
stable
set search_path = ''
as $$
  select d.criado_por from public.documentos d where d.id = p_documento_id;
$$;

comment on function private.documento_autor(uuid) is
  'Autoria do documento sem passar pelo RLS de documentos. Usada pela policy de insert de versao, que so deixa o papel local contribuidor versionar o que ele mesmo criou.';

create or replace function private.papel_na_pasta(p_pasta_id uuid)
returns text
language sql
security definer
stable
set search_path = ''
as $$
  with alvo as (
    select p.id, p.workspace_id, p.path, p.profundidade, p.setor_id
    from public.pastas p
    where p.id = p_pasta_id
  ),
  ancestrais as (
    select p.id, p.profundidade, p.herda_permissoes
    from public.pastas p, alvo a
    where p.workspace_id = a.workspace_id
      and (p.id = a.id or a.path like p.path || '/%')
  ),
  corte as (
    select coalesce(max(profundidade), 0) as nivel
    from ancestrais
    where herda_permissoes = false
  ),
  cadeia as (
    select an.id, an.profundidade
    from ancestrais an, corte c
    where an.profundidade >= c.nivel
  ),
  regras as (
    select c.profundidade, r.papel_local, r.efeito
    from cadeia c
    join public.pasta_permissoes r
      on r.pasta_id = c.id and r.documento_id is null
    where (r.expira_em is null or r.expira_em > now())
      and (
        (r.sujeito_tipo = 'usuario' and r.sujeito_usuario_id = (select auth.uid()))
        or (r.sujeito_tipo = 'setor' and (select private.pertence_ao_setor(r.sujeito_setor_id)))
        or (r.sujeito_tipo = 'papel' and exists (
              select 1
              from public.usuario_papeis up, alvo a
              where up.user_id = (select auth.uid())
                and up.papel = r.sujeito_papel
                and up.inicio <= now()
                and (up.fim is null or up.fim > now())
                and (up.setor_id is null or up.setor_id = a.setor_id)
            ))
      )
  ),
  efetivo as (
    select r.papel_local
    from regras r
    where r.profundidade = (select max(profundidade) from regras)
      and r.efeito = 'permitir'
      and not exists (
        select 1 from regras n
        where n.profundidade = r.profundidade
          and n.efeito = 'negar'
          and n.papel_local = r.papel_local
      )
    order by case r.papel_local
               when 'revisor' then 4
               when 'editor' then 3
               when 'contribuidor' then 2
               else 1
             end desc
    limit 1
  )
  select case
    when (select public.autorizar('operacao.administrar'::public.permissao, null::uuid))
      then 'revisor'
    -- Nao basta ter documento.permissionar: o papel precisa ter sido atribuido
    -- a este setor. Papel global nao vira revisor de pasta de setor alheio.
    when (select private.permissao_no_setor('documento.permissionar'::public.permissao, a.setor_id))
      then 'revisor'
    else coalesce(
      (select papel_local from efetivo),
      case
        when (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
          then 'leitor'
      end
    )
  end
  from alvo a;
$$;

comment on function private.papel_na_pasta(uuid) is
  'Papel local efetivo de auth.uid() sobre uma pasta: leitor, contribuidor, editor, revisor ou nulo. Soma as regras dos ancestrais pela ordem do caminho materializado, corta a cadeia na pasta mais proxima com herda_permissoes falso, faz o nivel mais proximo vencer e negar vencer permitir no mesmo nivel, como os dois bitmaps mask e permissions do Nextcloud Team folders. Papeis locais do rolemap.xml do Plone. A cadeia de ancestrais e resolvida por comparacao de path, por isso qualquer mudanca de caminho precisa ser propagada aos descendentes por public.pastas_recalcular_subarvore. Regra de setor por private.pertence_ao_setor, que recebe setor, e permissao por papel do proprio setor por private.permissao_no_setor. Le usuario_papeis diretamente porque e a funcao de private que as policies chamam em lugar disso, como manda a convencao da casa.';

create or replace function private.pode_classificar_documento(p_documento_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select coalesce(
    (select private.papel_na_pasta(d.pasta_id) = 'revisor'
       from public.documentos d
      where d.id = p_documento_id),
    false
  );
$$;

comment on function private.pode_classificar_documento(uuid) is
  'Verdadeiro para quem e revisor da pasta produtora do documento, independentemente do nivel de acesso. E o que sustenta a competencia de reclassificar e de conceder credencial nominal sobre documento sigiloso sem que o revisor passe a ler o binario nem o texto_extraido: quem le e private.pode_ver_documento, que sobre sigiloso exige credencial nominal e aal2. As policies documentos_update_revisor, pasta_permissoes_insert_revisor e pasta_permissoes_update_revisor chamam esta funcao, e nao private.papel_no_documento.';

create or replace function private.papel_no_documento(p_documento_id uuid)
returns text
language plpgsql
security definer
stable
set search_path = ''
as $$
declare
  v_doc     public.documentos%rowtype;
  v_regra   text;
  v_base    text;
  v_nominal text;
begin
  select * into v_doc from public.documentos where id = p_documento_id;
  if not found then
    return null;
  end if;

  -- Excecao propria do documento vence a heranca da pasta.
  with candidatas as (
    select r.papel_local, r.efeito
    from public.pasta_permissoes r
    where r.documento_id = v_doc.id
      and (r.expira_em is null or r.expira_em > now())
      and (
        (r.sujeito_tipo = 'usuario' and r.sujeito_usuario_id = (select auth.uid()))
        or (r.sujeito_tipo = 'setor' and (select private.pertence_ao_setor(r.sujeito_setor_id)))
        or (r.sujeito_tipo = 'papel' and exists (
              select 1 from public.usuario_papeis up
              where up.user_id = (select auth.uid())
                and up.papel = r.sujeito_papel
                and up.inicio <= now()
                and (up.fim is null or up.fim > now())
                and (up.setor_id is null or up.setor_id = v_doc.setor_id)
            ))
      )
  )
  select c.papel_local into v_regra
  from candidatas c
  where c.efeito = 'permitir'
    and not exists (
      select 1 from candidatas n
      where n.efeito = 'negar' and n.papel_local = c.papel_local
    )
  order by case c.papel_local
             when 'revisor' then 4
             when 'editor' then 3
             when 'contribuidor' then 2
             else 1
           end desc
  limit 1;

  v_base := coalesce(v_regra, private.papel_na_pasta(v_doc.pasta_id));

  if v_doc.nivel_acesso <> 'sigiloso' then
    return v_base;
  end if;

  -- Sigiloso, regra do SEI: abrir ou baixar exige sessao com aal2 e credencial
  -- nominal (linha com documento_id e sujeito_usuario_id), nunca grupo, nunca
  -- heranca e nunca papel de revisor da pasta. Sem credencial nominal esta
  -- funcao devolve nulo mesmo para quem private.papel_na_pasta ja apontou como
  -- revisor; a competencia de reclassificar e de conceder credencial continua
  -- viva por private.pode_classificar_documento, que nao abre o binario.
  if not (select private.exige_aal2()) then
    return null;
  end if;

  select r.papel_local into v_nominal
  from public.pasta_permissoes r
  where r.documento_id = v_doc.id
    and r.sujeito_tipo = 'usuario'
    and r.sujeito_usuario_id = (select auth.uid())
    and r.efeito = 'permitir'
    and (r.expira_em is null or r.expira_em > now())
  order by case r.papel_local
             when 'revisor' then 4
             when 'editor' then 3
             when 'contribuidor' then 2
             else 1
           end desc
  limit 1;

  return v_nominal;
end;
$$;

comment on function private.papel_no_documento(uuid) is
  'Papel local efetivo de auth.uid() sobre um documento: regra propria do documento vence a heranca da pasta, e o nivel sigiloso so passa com sessao aal2 mais credencial nominal, regra do SEI. Sobre sigiloso devolve nulo para quem nao tem credencial nominal, inclusive para o revisor da pasta produtora, porque quem classifica nao precisa ler: a classificacao e a concessao de credencial passam por private.pode_classificar_documento. Complementa private.papel_na_pasta, que responde apenas sobre a pasta, e e a funcao que as policies de leitura de documentos e documento_versoes chamam.';

create or replace function private.pode_ver_documento(p_documento_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select private.papel_no_documento(p_documento_id) is not null;
$$;

comment on function private.pode_ver_documento(uuid) is
  'Verdadeiro quando auth.uid() alcanca o documento pela pasta, por regra propria ou por credencial nominal com aal2. Usada nas policies de select de documentos e documento_versoes. Sobre documento sigiloso e falsa para quem nao tem credencial nominal, inclusive para o revisor da pasta.';

create or replace function private.pasta_vazia(p_pasta_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select not exists (select 1 from public.documentos d where d.pasta_id = p_pasta_id)
     and not exists (select 1 from public.pastas p where p.parent_id = p_pasta_id);
$$;

comment on function private.pasta_vazia(uuid) is
  'Verdadeiro quando a pasta nao tem subpasta nem documento. Existe porque a policy de delete de pastas, a unica de delete desta parte, so libera pasta vazia e nao raiz, e a checagem nao pode consultar documentos direto dentro da policy.';

revoke all on function private.permissao_no_setor(public.permissao, uuid) from public, anon;
revoke all on function private.tem_credencial_nominal(uuid)       from public, anon;
revoke all on function private.documento_autor(uuid)              from public, anon;
revoke all on function private.papel_na_pasta(uuid)               from public, anon;
revoke all on function private.pode_classificar_documento(uuid)   from public, anon;
revoke all on function private.papel_no_documento(uuid)           from public, anon;
revoke all on function private.pode_ver_documento(uuid)           from public, anon;
revoke all on function private.pasta_vazia(uuid)                  from public, anon;
grant execute on function private.permissao_no_setor(public.permissao, uuid) to authenticated;
grant execute on function private.tem_credencial_nominal(uuid)     to authenticated;
grant execute on function private.documento_autor(uuid)            to authenticated;
grant execute on function private.papel_na_pasta(uuid)             to authenticated;
grant execute on function private.pode_classificar_documento(uuid) to authenticated;
grant execute on function private.papel_no_documento(uuid)         to authenticated;
grant execute on function private.pode_ver_documento(uuid)         to authenticated;
grant execute on function private.pasta_vazia(uuid)                to authenticated;

-- ------------------------------------------------------------
-- 13. Triggers das pastas: caminho materializado, subarvore, raiz, nivel
-- ------------------------------------------------------------

create or replace function public.pastas_define_caminho()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_pai public.pastas%rowtype;
begin
  if new.parent_id is null then
    new.path := '/' || new.slug;
    new.profundidade := 1;
  else
    select * into v_pai from public.pastas where id = new.parent_id;
    if not found then
      raise exception 'pasta mae inexistente';
    end if;
    if v_pai.workspace_id <> new.workspace_id then
      raise exception 'pasta mae pertence a outro espaco';
    end if;
    if tg_op = 'UPDATE' and v_pai.path like old.path || '/%' then
      raise exception 'pasta nao pode ser movida para dentro da propria subarvore';
    end if;
    new.path := v_pai.path || '/' || new.slug;
    new.profundidade := v_pai.profundidade + 1;
  end if;
  if new.profundidade > 6 then
    raise exception 'profundidade maxima da arvore de pastas e de seis niveis';
  end if;
  return new;
end;
$$;

comment on function public.pastas_define_caminho() is
  'Materializa pastas.path e pastas.profundidade a partir da pasta mae e recusa mover pasta para dentro da propria subarvore. Caminho materializado transposto do model Folder do Papermark. Responde so pela linha alterada; os descendentes ficam com public.pastas_recalcular_subarvore.';

create or replace function public.pastas_recalcular_subarvore(p_pasta_id uuid)
returns integer
language plpgsql
set search_path = ''
as $$
declare
  v_pai       public.pastas%rowtype;
  v_afetadas  integer := 0;
  v_max       smallint := 0;
begin
  select * into v_pai from public.pastas where id = p_pasta_id;
  if not found then
    return 0;
  end if;

  -- Uma unica varredura recursiva: cada descendente recebe o caminho ja
  -- recalculado do proprio pai mais o seu slug, e a profundidade
  -- correspondente. A CTE le a arvore antes da escrita, e os slugs nao mudam,
  -- por isso a ordem de atualizacao das linhas nao importa.
  with recursive subarvore as (
    select f.id,
           (v_pai.path || '/' || f.slug) as novo_path,
           (v_pai.profundidade + 1)::smallint as nova_profundidade
      from public.pastas f
     where f.parent_id = v_pai.id
    union all
    select f.id,
           (s.novo_path || '/' || f.slug),
           (s.nova_profundidade + 1)::smallint
      from public.pastas f
      join subarvore s on f.parent_id = s.id
  ),
  aplicado as (
    update public.pastas alvo
       set path = s.novo_path,
           profundidade = s.nova_profundidade
      from subarvore s
     where alvo.id = s.id
       and (alvo.path is distinct from s.novo_path
            or alvo.profundidade is distinct from s.nova_profundidade)
    returning alvo.id, alvo.profundidade
  )
  select count(*)::integer, coalesce(max(profundidade), 0)::smallint
    into v_afetadas, v_max
    from aplicado;

  if v_max > 6 then
    raise exception 'profundidade maxima da arvore de pastas e de seis niveis';
  end if;

  return v_afetadas;
end;
$$;

comment on function public.pastas_recalcular_subarvore(uuid) is
  'Reescreve path e profundidade de todos os descendentes de uma pasta a partir do caminho novo dela, em uma unica varredura recursiva, respeitando o teto de seis niveis. Existe porque private.papel_na_pasta resolve a cadeia de ancestrais por comparacao de path: sem esse recalculo, um simples renomear deixa os descendentes com o caminho antigo, eles param de casar com o path do ancestral e a heranca de permissoes de uma subarvore inteira e desfeita em silencio, sem erro e sem trilha. A versao anterior desta parte tocava apenas atualizado_em dos filhos diretos, e o trigger de caminho, declarado before insert or update of parent_id, slug, nunca disparava nessa cascata.';

create or replace function public.pastas_move_subarvore()
returns trigger language plpgsql set search_path = '' as $$
begin
  if new.path is distinct from old.path
     and coalesce(current_setting('cvrj.pastas_recalculando', true), '') <> 'on' then
    -- Marca de sessao local a transacao para que o recalculo dos descendentes,
    -- que tambem muda path, nao reentre neste trigger a cada nivel.
    perform set_config('cvrj.pastas_recalculando', 'on', true);
    perform public.pastas_recalcular_subarvore(new.id);
    perform set_config('cvrj.pastas_recalculando', 'off', true);
  end if;
  return null;
end;
$$;

comment on function public.pastas_move_subarvore() is
  'Chama public.pastas_recalcular_subarvore sempre que pastas.path muda, seja por mover, seja por renomear. Guardada por marca de sessao local a transacao para nao reentrar em cascata.';

create or replace function public.pastas_protege_raiz()
returns trigger language plpgsql set search_path = '' as $$
begin
  if tg_op = 'DELETE' then
    if old.raiz then
      raise exception 'pasta raiz criada por seed nao pode ser apagada';
    end if;
    if not private.pasta_vazia(old.id) then
      raise exception 'pasta com subpasta ou documento nao pode ser apagada';
    end if;
    return old;
  end if;
  if old.raiz and (new.slug is distinct from old.slug
                   or new.parent_id is distinct from old.parent_id) then
    raise exception 'pasta raiz criada por seed nao pode ser movida nem renomeada';
  end if;
  return new;
end;
$$;

comment on function public.pastas_protege_raiz() is
  'Recusa mover, renomear ou apagar pasta raiz de seed, e recusa apagar pasta com conteudo, inclusive contra chamada com service_role. Nao barra o recalculo de path e profundidade dos descendentes, que nao toca slug nem parent_id.';

create or replace function public.pastas_recalcula_nivel()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_ids uuid[];
begin
  v_ids := array_remove(array[
    case when tg_op <> 'INSERT' then old.pasta_id end,
    case when tg_op <> 'DELETE' then new.pasta_id end
  ], null);
  if array_length(v_ids, 1) is null then
    return null;
  end if;
  update public.pastas p
     set nivel_acesso_maximo = greatest(
           coalesce((
             select case
               when bool_or(d.nivel_acesso = 'sigiloso') then 'sigiloso'
               when bool_or(d.nivel_acesso = 'restrito') then 'restrito'
               else 'publico'
             end
             from public.documentos d
             where d.pasta_id = p.id and d.status <> 'erased'
           ), 'publico'),
           -- Piso da pasta de setor restrito por padrao: esvaziar a pasta nao
           -- devolve o rotulo a publico.
           case when exists (
             select 1 from public.setores s
             where s.id = p.setor_id and s.restrito_por_padrao
           ) then 'restrito' else 'publico' end
         )
   where p.id = any(v_ids);
  return null;
end;
$$;

comment on function public.pastas_recalcula_nivel() is
  'Mantem pastas.nivel_acesso_maximo com o maior nivel entre os documentos contidos, com piso restrito nas pastas de setor marcado como restrito_por_padrao. Regra do conjunto do SEI, so para exibicao; a permissao real continua vindo de pasta_permissoes. A comparacao por greatest funciona porque publico, restrito e sigiloso estao em ordem alfabetica crescente de sigilo (publico < restrito < sigiloso).';

drop trigger if exists pastas_define_caminho on public.pastas;
create trigger pastas_define_caminho
  before insert or update of parent_id, slug on public.pastas
  for each row execute function public.pastas_define_caminho();

drop trigger if exists pastas_protege_raiz on public.pastas;
create trigger pastas_protege_raiz
  before update or delete on public.pastas
  for each row execute function public.pastas_protege_raiz();

drop trigger if exists pastas_toca on public.pastas;
create trigger pastas_toca
  before update on public.pastas
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists pastas_move_subarvore on public.pastas;
create trigger pastas_move_subarvore
  after update on public.pastas
  for each row when (new.path is distinct from old.path)
  execute function public.pastas_move_subarvore();

revoke all on function public.pastas_recalcular_subarvore(uuid) from public, anon;
grant execute on function public.pastas_recalcular_subarvore(uuid) to authenticated;

-- ------------------------------------------------------------
-- 14. Triggers dos documentos: metadados, retencao, protocolo, guarda
-- ------------------------------------------------------------

create or replace function public.documentos_valida_metadados()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_tipo    public.tipos_documentais%rowtype;
  v_pasta   public.pastas%rowtype;
  v_setor_restrito boolean := false;
  v_obrig   jsonb;
  v_campo   text;
  v_ordem constant jsonb := '{"publico":0,"restrito":1,"sigiloso":2}'::jsonb;
begin
  select * into v_tipo from public.tipos_documentais where id = new.tipo_documental_id;
  if not found then
    raise exception 'tipo documental inexistente';
  end if;
  if tg_op = 'INSERT' and not v_tipo.ativo then
    raise exception 'tipo documental % esta inativo e nao aceita novos documentos', v_tipo.nome;
  end if;

  select * into v_pasta from public.pastas where id = new.pasta_id;
  if not found then
    raise exception 'pasta inexistente';
  end if;
  if v_pasta.workspace_id <> new.workspace_id then
    raise exception 'pasta pertence a outro espaco';
  end if;

  if tg_op = 'INSERT' or new.pasta_id is distinct from old.pasta_id then
    new.setor_id := coalesce(new.setor_id, v_pasta.setor_id);
  end if;

  select coalesce(s.restrito_por_padrao, false) into v_setor_restrito
    from public.setores s where s.id = v_pasta.setor_id;
  v_setor_restrito := coalesce(v_setor_restrito, false);

  -- Envio simples: o wizard nao pergunta classificacao. Quando nivel_acesso vem
  -- no valor padrao da coluna, o banco deriva do tipo documental; quem quiser um
  -- nivel acima do padrao envia sigiloso, e reclassificar depois e ato de
  -- revisor com aal2, em documentos_guarda_colunas.
  if tg_op = 'INSERT' and new.nivel_acesso = 'restrito' then
    new.nivel_acesso := v_tipo.nivel_acesso_padrao;
  end if;

  -- Medida tecnica da pasta de setor marcado como restrito_por_padrao, hoje o
  -- setor Saude: a coluna setores.restrito_por_padrao existia no modelo sem
  -- nenhum leitor, e esta e a medida prometida. O enquadramento de risco do
  -- tratamento continua sendo decisao da Diretoria, nao consequencia desta
  -- linha de codigo.
  if v_setor_restrito and new.nivel_acesso = 'publico' then
    new.nivel_acesso := 'restrito';
  end if;

  -- Hipotese legal derivada do tipo, para que o envio nao exija duas decisoes
  -- arquivisticas de coordenador e de voluntario.
  if tg_op = 'INSERT' and new.nivel_acesso <> 'publico' and new.hipotese_legal is null then
    new.hipotese_legal := case
      when v_setor_restrito then 'dados_sensiveis_lgpd_art11'
      when v_tipo.contem_dados_pessoais then 'dados_pessoais_lgpd_art7'
      else null
    end;
    if new.hipotese_legal is null then
      raise exception 'documento % exige hipotese legal e o tipo % nao tem hipotese padrao: escolha uma em hipoteses_legais',
        new.titulo, v_tipo.nome;
    end if;
  end if;

  if v_setor_restrito and new.hipotese_legal is null then
    raise exception 'pasta de setor restrito por padrao nao aceita documento sem hipotese legal';
  end if;

  if (v_ordem ->> new.nivel_acesso)::int < (v_ordem ->> v_tipo.nivel_acesso_padrao)::int then
    raise exception 'nivel de acesso abaixo do minimo do tipo documental, que e %',
      v_tipo.nivel_acesso_padrao;
  end if;

  -- SEI e SUAP: restrito por padrao quando ha dado pessoal.
  if v_tipo.contem_dados_pessoais and new.nivel_acesso = 'publico' then
    raise exception 'tipo documental com dado pessoal nao aceita nivel de acesso publico';
  end if;

  v_obrig := coalesce(
    v_tipo.metadados_obrigatorios -> 'required',
    v_tipo.metadados_obrigatorios -> 'campos',
    '[]'::jsonb
  );
  if jsonb_typeof(v_obrig) = 'array' and new.status <> 'erased' then
    for v_campo in select jsonb_array_elements_text(v_obrig) loop
      if v_campo = 'data_referencia' then
        -- data_referencia e coluna, nao chave do jsonb: o dado nao e digitado
        -- duas vezes. O significado por tipo esta no comentario da coluna.
        if new.data_referencia is null then
          raise exception 'o tipo % exige data de referencia', v_tipo.nome;
        end if;
      elsif not (new.metadados ? v_campo)
         or coalesce(new.metadados ->> v_campo, '') = '' then
        raise exception 'metadado obrigatorio ausente para o tipo %: %', v_tipo.nome, v_campo;
      end if;
    end loop;
  end if;

  -- Retencao calculada, e-ARQ Brasil 2 e MROSC art. 68. Enquanto o tipo estiver
  -- com prazo_pendente_decisao, retencao_ate fica nula: o banco nao inventa
  -- prazo que a Diretoria ainda nao fixou (D27).
  if v_tipo.guarda_permanente or v_tipo.prazo_pendente_decisao then
    new.retencao_ate := null;
  elsif new.data_referencia is not null and v_tipo.prazo_guarda_anos is not null then
    new.retencao_ate := new.data_referencia + (v_tipo.prazo_guarda_anos || ' years')::interval;
  end if;

  return new;
end;
$$;

comment on function public.documentos_valida_metadados() is
  'Recusa documento cujos metadados nao satisfazem o esquema do tipo documental, deriva no envio o nivel de acesso do tipo e a hipotese legal padrao, eleva a restrito e exige hipotese na pasta de setor marcado como restrito_por_padrao, recusa nivel publico em tipo com dado pessoal, herda o setor da pasta e calcula retencao_ate a partir da data de referencia e do prazo de guarda, deixando-a nula enquanto o prazo do tipo estiver pendente de decisao. Vocabulario de metadados do e-ARQ Brasil 2; restrito por padrao quando ha dado pessoal vem do SEI e do SUAP.';

create or replace function public.documentos_numera_registro()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_tipo   public.tipos_documentais%rowtype;
  v_ano    text;
  v_seq    int;
  v_prefixo text;
begin
  if new.numero_registro is not null then
    return new;
  end if;
  select * into v_tipo from public.tipos_documentais where id = new.tipo_documental_id;
  if v_tipo.tipo_ato not in ('oficio', 'ata_junta', 'ata_assembleia', 'ata_diretoria',
                             'parecer', 'prestacao_contas') then
    return new;
  end if;
  v_prefixo := upper(replace(v_tipo.tipo_ato::text, '_', '-'));
  v_ano := to_char(coalesce(new.data_referencia, current_date), 'YYYY');
  -- Serializa a numeracao por espaco, tipo e ano, no molde do protocolo do SEI.
  perform pg_advisory_xact_lock(hashtext(new.workspace_id::text || v_prefixo || v_ano));
  select coalesce(max(split_part(d.numero_registro, '/', 2)::int), 0) + 1
    into v_seq
    from public.documentos d
   where d.workspace_id = new.workspace_id
     and d.numero_registro like v_prefixo || '-' || v_ano || '/%';
  new.numero_registro := v_prefixo || '-' || v_ano || '/' || lpad(v_seq::text, 4, '0');
  return new;
end;
$$;

comment on function public.documentos_numera_registro() is
  'Gera o numero de protocolo por espaco, tipo e ano para oficio, atas, parecer e prestacao de contas, serializado por advisory lock. Padrao de protocolo do SEI.';

create or replace function public.documentos_guarda_colunas()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_papel       text;
  v_classifica  boolean;
  v_por_rpc     boolean;
  v_publicando  boolean;
begin
  -- Jobs de pg_cron e rotinas de servico rodam sem JWT: nao ha papel a conferir.
  if (select auth.uid()) is null then
    return new;
  end if;

  v_papel := private.papel_no_documento(old.id);
  v_classifica := private.pode_classificar_documento(old.id);

  -- Marcador de sessao definido pela RPC de publicacao, criada na parte de
  -- autorizacao. Sem ele, nenhuma mudanca de estado passa sem papel revisor.
  v_por_rpc := coalesce(current_setting('cvrj.publicacao_autorizada', true), '') = 'on';
  v_publicando := old.status = 'draft'
    and new.status = 'current'
    and new.nivel_acesso is not distinct from old.nivel_acesso
    and new.hipotese_legal is not distinct from old.hipotese_legal
    and new.lixeira_em is not distinct from old.lixeira_em
    and new.eliminado_em is not distinct from old.eliminado_em;

  if (new.nivel_acesso is distinct from old.nivel_acesso
      or new.hipotese_legal is distinct from old.hipotese_legal
      or new.lixeira_em is distinct from old.lixeira_em
      or new.eliminado_em is distinct from old.eliminado_em
      or new.status is distinct from old.status)
     and not (coalesce(v_papel, '') = 'revisor' or v_classifica)
     and not (v_publicando and v_por_rpc) then
    raise exception 'so o revisor da pasta altera nivel de acesso, hipotese legal, estado, lixeira ou eliminacao; a passagem de minuta a vigente entra pela RPC de publicacao';
  end if;

  if (new.nivel_acesso is distinct from old.nivel_acesso
      or new.hipotese_legal is distinct from old.hipotese_legal)
     and not (select private.exige_aal2()) then
    raise exception 'alterar o nivel de acesso ou a hipotese legal exige sessao com segundo fator verificado';
  end if;

  if old.eliminado_em is not null
     and (new.titulo is distinct from old.titulo
          or new.metadados is distinct from old.metadados) then
    raise exception 'documento eliminado nao volta a receber titulo nem metadados';
  end if;

  return new;
end;
$$;

comment on function public.documentos_guarda_colunas() is
  'Restringe por papel local quais colunas mudam em update: nivel de acesso, hipotese legal, estado, lixeira e eliminacao so pelo revisor da pasta, e alterar nivel de acesso ou hipotese legal so com aal2, como manda a convencao de escrita de decisao. Sobre documento sigiloso o revisor e reconhecido por private.pode_classificar_documento, que nao abre o binario. Transicoes legitimas de documentos.status e por onde cada uma entra: draft para current so pela RPC de publicacao da parte de autorizacao, reconhecida por auth.uid() nulo (job sem JWT) ou pelo marcador de sessao cvrj.publicacao_autorizada, e nunca direto pelo cliente; draft ou current para archived, pelo revisor na tela; draft, current ou archived para trashed, por public.enviar_para_lixeira; trashed para current, por public.restaurar_documento; qualquer estado para erased, so por public.eliminar_documento, com motivo escrito e aal2. Sem a abertura de draft para current nenhuma acao levava o documento a vigente e o documento aprovado ficaria em minuta para sempre.';

create or replace function public.documentos_bloqueia_eliminacao()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_tipo  public.tipos_documentais%rowtype;
  v_tem   boolean;
begin
  if old.eliminado_em is not null or new.eliminado_em is null then
    return new;
  end if;
  select * into v_tipo from public.tipos_documentais where id = new.tipo_documental_id;
  if v_tipo.guarda_permanente then
    raise exception 'tipo documental de guarda permanente nunca e eliminado';
  end if;
  -- Prazo pendente de decisao nao bloqueia: prazo que a Diretoria ainda nao
  -- fixou nao pode travar o direito de eliminacao do titular.
  if not v_tipo.pode_eliminar_antes_do_prazo
     and not v_tipo.prazo_pendente_decisao
     and (new.retencao_ate is null or new.retencao_ate > current_date) then
    raise exception 'eliminacao bloqueada ate o fim do prazo de guarda (%)', new.retencao_ate;
  end if;

  -- A parte de autorizacao e assinatura pode nao existir ainda; a checagem e
  -- feita so quando as tabelas dela estiverem criadas.
  if to_regclass('public.assinaturas') is not null then
    execute 'select exists (select 1 from public.assinaturas a where a.documento_id = $1)'
      into v_tem using old.id;
    if v_tem then
      raise exception 'documento com assinatura registrada nao e eliminado';
    end if;
  end if;
  if to_regclass('public.autorizacoes') is not null then
    execute 'select exists (select 1 from public.autorizacoes z
               where z.objeto_tipo = ''documentos'' and z.objeto_id = $1
                 and z.concluida_em is null and z.retirada_em is null)'
      into v_tem using old.id;
    if v_tem then
      raise exception 'documento com tramite aberto nao e eliminado';
    end if;
  end if;
  return new;
end;
$$;

comment on function public.documentos_bloqueia_eliminacao() is
  'Recusa eliminar documento de guarda permanente, dentro do prazo de guarda de tipo que nao aceita eliminacao antecipada, com assinatura registrada ou com tramite aberto. Prazo de dez anos da prestacao de contas vem do art. 68 do MROSC. Nao bloqueia por prazo enquanto o tipo estiver com prazo_pendente_decisao.';

create or replace function public.documentos_recusa_delete()
returns trigger language plpgsql set search_path = '' as $$
begin
  raise exception 'documentos nunca aceita delete: eliminar e update por public.eliminar_documento';
end;
$$;

comment on function public.documentos_recusa_delete() is
  'Nada e apagado na biblioteca. A saida e sempre update de coluna de data: lixeira_em e depois eliminado_em.';

drop trigger if exists documentos_valida_metadados on public.documentos;
create trigger documentos_valida_metadados
  before insert or update on public.documentos
  for each row execute function public.documentos_valida_metadados();

drop trigger if exists documentos_numera_registro on public.documentos;
create trigger documentos_numera_registro
  before insert on public.documentos
  for each row execute function public.documentos_numera_registro();

drop trigger if exists documentos_guarda_colunas on public.documentos;
create trigger documentos_guarda_colunas
  before update on public.documentos
  for each row execute function public.documentos_guarda_colunas();

drop trigger if exists documentos_bloqueia_eliminacao on public.documentos;
create trigger documentos_bloqueia_eliminacao
  before update on public.documentos
  for each row execute function public.documentos_bloqueia_eliminacao();

drop trigger if exists documentos_recusa_delete on public.documentos;
create trigger documentos_recusa_delete
  before delete on public.documentos
  for each row execute function public.documentos_recusa_delete();

drop trigger if exists documentos_toca on public.documentos;
create trigger documentos_toca
  before update on public.documentos
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists documentos_recalcula_nivel_da_pasta on public.documentos;
create trigger documentos_recalcula_nivel_da_pasta
  after insert or update of nivel_acesso, pasta_id, status on public.documentos
  for each row execute function public.pastas_recalcula_nivel();

-- ------------------------------------------------------------
-- 15. Triggers das versoes: numeracao, primaria, imutabilidade
-- ------------------------------------------------------------

create or replace function public.documento_versoes_numera()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_doc public.documentos%rowtype;
  v_ha  boolean;
begin
  select * into v_doc from public.documentos where id = new.documento_id;
  if not found then
    raise exception 'documento inexistente';
  end if;
  new.workspace_id := v_doc.workspace_id;

  if coalesce(new.numero, 0) = 0 then
    perform pg_advisory_xact_lock(hashtext('documento_versoes:' || new.documento_id::text));
    select coalesce(max(v.numero), 0) + 1 into new.numero
      from public.documento_versoes v where v.documento_id = new.documento_id;
  end if;

  select exists (select 1 from public.documento_versoes v
                  where v.documento_id = new.documento_id and v.is_primary)
    into v_ha;
  if not v_ha then
    new.is_primary := true;
  end if;
  return new;
end;
$$;

comment on function public.documento_versoes_numera() is
  'Numera a versao dentro do documento, herda o espaco do documento e marca a primeira versao como primaria. Numeracao por documento transposta de versionNumber com unicidade por documentId no DocumentVersion do Papermark. Quando ja existe primaria, a versao nova entra como nao primaria: promover e trocar de primaria e ato proprio, por public.definir_versao_primaria.';

create or replace function public.documento_versoes_uma_primaria()
returns trigger language plpgsql set search_path = '' as $$
begin
  if new.is_primary then
    update public.documento_versoes v
       set is_primary = false
     where v.documento_id = new.documento_id
       and v.id <> new.id
       and v.is_primary;
  end if;
  return new;
end;
$$;

comment on function public.documento_versoes_uma_primaria() is
  'Rebaixa a primaria anterior antes de a linha promovida entrar no indice unico parcial documento_versoes_documento_id_primaria_idx. Roda em trigger before update of is_primary de proposito: o indice e conferido durante o comando, antes de qualquer trigger after row, e por isso a versao anterior desta parte, com trigger after, falhava com violacao de unicidade e nunca chegava a rebaixar a anterior. A troca completa esta concentrada em public.definir_versao_primaria.';

create or replace function public.documento_versoes_imutavel()
returns trigger language plpgsql set search_path = '' as $$
begin
  if new.documento_id is distinct from old.documento_id
     or new.numero is distinct from old.numero
     or new.hash_sha256 is distinct from old.hash_sha256
     or new.size_bytes is distinct from old.size_bytes
     or new.content_type is distinct from old.content_type
     or new.storage_backend is distinct from old.storage_backend
     or new.origem is distinct from old.origem
     or new.criado_em is distinct from old.criado_em then
    raise exception 'versao de documento e imutavel: corrigir e subir nova versao';
  end if;
  -- storage_path e texto_extraido so mudam de valor para nulo, na eliminacao.
  if new.storage_path is distinct from old.storage_path
     and new.storage_path is not null
     and old.storage_path is not null then
    raise exception 'caminho de armazenamento da versao nao e reescrito';
  end if;
  if old.eliminada_em is not null and new.eliminada_em is null then
    raise exception 'versao eliminada nao volta atras';
  end if;
  return new;
end;
$$;

comment on function public.documento_versoes_imutavel() is
  'Congela hash, numero, tamanho, tipo, backend e origem da versao. Deixa passar apenas is_primary, motivo, os campos de extracao (status, tentativas e erro), os campos de reconferencia de hash, o resultado do validador do ITI e a anulacao de storage_path e texto_extraido na eliminacao, que preserva o hash.';

create or replace function public.documento_versoes_recusa_delete()
returns trigger language plpgsql set search_path = '' as $$
begin
  raise exception 'documento_versoes nunca aceita delete: eliminar e update de eliminada_em';
end;
$$;

comment on function public.documento_versoes_recusa_delete() is
  'Nada e apagado: o hash sobrevive a eliminacao do binario, como manda a secao 5 da pesquisa de rastreabilidade.';

drop trigger if exists documento_versoes_numera on public.documento_versoes;
create trigger documento_versoes_numera
  before insert on public.documento_versoes
  for each row execute function public.documento_versoes_numera();

drop trigger if exists documento_versoes_imutavel on public.documento_versoes;
create trigger documento_versoes_imutavel
  before update on public.documento_versoes
  for each row execute function public.documento_versoes_imutavel();

drop trigger if exists documento_versoes_recusa_delete on public.documento_versoes;
create trigger documento_versoes_recusa_delete
  before delete on public.documento_versoes
  for each row execute function public.documento_versoes_recusa_delete();

drop trigger if exists documento_versoes_uma_primaria on public.documento_versoes;
create trigger documento_versoes_uma_primaria
  before update of is_primary on public.documento_versoes
  for each row when (new.is_primary)
  execute function public.documento_versoes_uma_primaria();

-- ------------------------------------------------------------
-- 16. Triggers de permissoes, links e modelos
-- ------------------------------------------------------------

create or replace function public.pasta_permissoes_herda_espaco()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_pasta public.pastas%rowtype;
  v_doc   public.documentos%rowtype;
begin
  select * into v_pasta from public.pastas where id = new.pasta_id;
  if not found then
    raise exception 'pasta inexistente';
  end if;
  new.workspace_id := v_pasta.workspace_id;
  if new.documento_id is not null then
    select * into v_doc from public.documentos where id = new.documento_id;
    if not found or v_doc.pasta_id <> new.pasta_id then
      raise exception 'a regra do documento precisa apontar a pasta em que ele esta';
    end if;
  end if;
  return new;
end;
$$;

comment on function public.pasta_permissoes_herda_espaco() is
  'Herda o espaco da pasta e exige que a excecao por documento aponte a pasta em que o documento esta, para que a cadeia de ancestrais continue coerente. E security definer de proposito: como gatilho invoker ele lia public.documentos pela sessao de quem escreve, e o documento sigiloso nao aparece para quem ainda nao tem credencial nominal, entao a primeira concessao abortava aqui antes de a policy pasta_permissoes_insert_revisor ser avaliada, e o nivel sigiloso virava porta de mao unica. O gatilho so le e valida coerencia; quem decide se a pessoa pode conceder continua sendo a policy, que roda sobre a sessao real. Defeito encontrado pela suite pgTAP do anexo 02b.';

create or replace function public.documento_links_recusa_sigiloso()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_doc public.documentos%rowtype;
begin
  select * into v_doc from public.documentos where id = new.documento_id;
  if not found then
    raise exception 'documento inexistente';
  end if;
  new.workspace_id := v_doc.workspace_id;
  if v_doc.nivel_acesso = 'sigiloso' then
    raise exception 'link interno nunca e emitido para documento sigiloso';
  end if;
  if v_doc.status in ('trashed', 'erased') then
    raise exception 'documento na lixeira ou eliminado nao recebe link';
  end if;
  if new.versao_id is not null then
    if not exists (select 1 from public.documento_versoes v
                    where v.id = new.versao_id and v.documento_id = new.documento_id) then
      raise exception 'a versao apontada nao pertence a este documento';
    end if;
  end if;
  return new;
end;
$$;

comment on function public.documento_links_recusa_sigiloso() is
  'Recusa link interno para documento sigiloso, na lixeira ou eliminado, e confere que a versao fixada pertence ao documento.';

drop trigger if exists pasta_permissoes_herda_espaco on public.pasta_permissoes;
create trigger pasta_permissoes_herda_espaco
  before insert or update on public.pasta_permissoes
  for each row execute function public.pasta_permissoes_herda_espaco();

drop trigger if exists documento_links_recusa_sigiloso on public.documento_links;
create trigger documento_links_recusa_sigiloso
  before insert or update on public.documento_links
  for each row execute function public.documento_links_recusa_sigiloso();

drop trigger if exists tipos_documentais_toca on public.tipos_documentais;
create trigger tipos_documentais_toca
  before update on public.tipos_documentais
  for each row execute function public.tocar_atualizado_em();

drop trigger if exists modelos_documento_toca on public.modelos_documento;
create trigger modelos_documento_toca
  before update on public.modelos_documento
  for each row execute function public.tocar_atualizado_em();

-- ------------------------------------------------------------
-- 17. RPCs da lixeira, da restauracao, da eliminacao, da versao primaria
--     e do link. security invoker com search_path vazio, a escolha ja
--     declarada no ARQUITETURA.md da Redacao para submit_content_for_approval
--     e vote_on_approval, para que o RLS continue valendo dentro da funcao.
-- ------------------------------------------------------------

create or replace function public.enviar_para_lixeira(p_documento_id uuid)
returns public.documentos
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_doc public.documentos%rowtype;
begin
  update public.documentos d
     set status = 'trashed',
         lixeira_em = now(),
         pasta_original_id = coalesce(d.pasta_original_id, d.pasta_id)
   where d.id = p_documento_id
     and d.status in ('draft', 'current', 'archived')
  returning * into v_doc;
  if not found then
    raise exception 'documento inexistente, ja na lixeira ou fora do seu alcance';
  end if;
  return v_doc;
end;
$$;

comment on function public.enviar_para_lixeira(uuid) is
  'Envia o documento para a lixeira guardando a pasta original, sem tocar no binario. Lixeira com original_location transposta de group_folders_trash do Nextcloud Team folders. Chamada por Server Action apos requireSession; o RLS de documentos e o trigger de guarda de colunas exigem papel revisor.';

create or replace function public.restaurar_documento(p_documento_id uuid)
returns public.documentos
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_doc  public.documentos%rowtype;
  v_alvo uuid;
begin
  select d.pasta_original_id into v_alvo
    from public.documentos d where d.id = p_documento_id;
  if v_alvo is null or not exists (select 1 from public.pastas p where p.id = v_alvo) then
    -- A pasta original pode nao existir mais: volta para a raiz do setor.
    select p.id into v_alvo
      from public.pastas p, public.documentos d
     where d.id = p_documento_id
       and p.workspace_id = d.workspace_id
       and p.setor_id is not distinct from d.setor_id
       and p.raiz
     order by p.profundidade
     limit 1;
  end if;
  if v_alvo is null then
    raise exception 'nao ha pasta de destino para restaurar este documento';
  end if;

  update public.documentos d
     set status = 'current',
         lixeira_em = null,
         pasta_id = v_alvo,
         pasta_original_id = null
   where d.id = p_documento_id
     and d.status = 'trashed'
  returning * into v_doc;
  if not found then
    raise exception 'documento nao esta na lixeira ou esta fora do seu alcance';
  end if;
  return v_doc;
end;
$$;

comment on function public.restaurar_documento(uuid) is
  'Restaura documento da lixeira para a pasta original, ou para a raiz do setor quando a original nao existe mais.';

create or replace function public.definir_versao_primaria(p_versao_id uuid)
returns public.documento_versoes
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_versao public.documento_versoes%rowtype;
begin
  select * into v_versao from public.documento_versoes v where v.id = p_versao_id;
  if not found then
    raise exception 'versao inexistente ou fora do seu alcance';
  end if;
  if v_versao.eliminada_em is not null then
    raise exception 'versao eliminada nao volta a ser primaria';
  end if;
  if v_versao.is_primary then
    return v_versao;
  end if;

  -- Ordem obrigatoria: rebaixa a anterior e so entao promove a nova. O indice
  -- unico parcial e conferido durante cada comando, nao no fim da transacao.
  update public.documento_versoes v
     set is_primary = false
   where v.documento_id = v_versao.documento_id
     and v.id <> p_versao_id
     and v.is_primary;

  update public.documento_versoes v
     set is_primary = true
   where v.id = p_versao_id
  returning * into v_versao;
  if not found then
    raise exception 'versao fora do seu alcance para promocao';
  end if;
  return v_versao;
end;
$$;

comment on function public.definir_versao_primaria(uuid) is
  'Troca a versao primaria de um documento na ordem que o banco aceita: rebaixa a anterior e depois promove a escolhida. O indice unico parcial documento_versoes_documento_id_primaria_idx e conferido durante o comando, antes de qualquer trigger after row, e por isso a promocao direta falhava com violacao de unicidade. O RLS de documento_versoes continua valendo: promover exige papel local editor ou revisor.';

create or replace function public.eliminar_documento(p_documento_id uuid, p_motivo text)
returns public.documentos
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_doc public.documentos%rowtype;
begin
  if coalesce(char_length(trim(p_motivo)), 0) < 5 then
    raise exception 'a eliminacao exige motivo escrito';
  end if;
  if not (select private.exige_aal2()) then
    raise exception 'eliminar documento exige sessao com segundo fator verificado';
  end if;

  -- Procedimento de eliminacao da secao 5 da pesquisa de rastreabilidade:
  -- apaga o binario e o texto, mantem o hash, o numero e o tamanho, anula a
  -- autoria e deixa um hash sem original mais um uuid orfao.
  update public.documento_versoes v
     set storage_path = null,
         texto_extraido = null,
         extracao_status = 'no_text',
         enviado_por = null,
         eliminada_em = coalesce(v.eliminada_em, now())
   where v.documento_id = p_documento_id;

  update public.documentos d
     set status = 'erased',
         eliminado_em = now(),
         lixeira_em = null,
         titulo = '[eliminado]',
         descricao = null,
         tags = '{}',
         metadados = '{}',
         criado_por = null
   where d.id = p_documento_id
     and d.eliminado_em is null
  returning * into v_doc;
  if not found then
    raise exception 'documento inexistente, ja eliminado ou fora do seu alcance';
  end if;
  return v_doc;
end;
$$;

comment on function public.eliminar_documento(uuid, text) is
  'Elimina o documento apagando o binario e o texto extraido, anulando titulo, descricao, tags, metadados e autoria, e mantendo hash, numero, tamanho e datas, o que responde ao art. 18 da LGPD sem quebrar a cadeia de auditoria. O evento documento.eliminado e gravado em auditoria.eventos pela Server Action que chama esta funcao, com hash_arquivo e codigo neutro de fluxo, sem dado pessoal.';

create or replace function public.resolver_link_documento(p_slug text)
returns table (
  documento_id      uuid,
  versao_id         uuid,
  titulo            text,
  numero            integer,
  storage_backend   text,
  storage_path      text,
  content_type      text,
  size_bytes        bigint,
  hash_sha256       text,
  permite_download  boolean
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_link public.documento_links%rowtype;
begin
  -- Abrir o link exige sessao: nenhum conteudo sai para anon.
  if (select auth.uid()) is null then
    raise exception 'link interno exige sessao autenticada';
  end if;
  select * into v_link from public.documento_links l where l.slug = p_slug;
  if not found or v_link.revogado_em is not null or v_link.expira_em <= now() then
    raise exception 'link inexistente, revogado ou expirado';
  end if;
  if not (select private.pertence_ao_espaco(v_link.workspace_id)) then
    raise exception 'link de outro espaco';
  end if;

  update public.documento_links l
     set acessos = l.acessos + 1,
         ultimo_acesso_em = now()
   where l.id = v_link.id;

  return query
    select d.id, v.id, d.titulo, v.numero, v.storage_backend,
           -- Sem permissao de download nao sai caminho de armazenamento: a
           -- rota /api/biblioteca/arquivo/[versaoId] nao tem o que entregar.
           case when v_link.permite_download then v.storage_path else null end,
           v.content_type, v.size_bytes, v.hash_sha256, v_link.permite_download
      from public.documentos d
      join public.pastas pa on pa.id = d.pasta_id
      join public.documento_versoes v
        on v.documento_id = d.id
       and (v.id = v_link.versao_id or (v_link.versao_id is null and v.is_primary))
     where d.id = v_link.documento_id
       and d.nivel_acesso <> 'sigiloso'
       and pa.nivel_acesso_maximo <> 'sigiloso'
       and d.status not in ('trashed', 'erased');
end;
$$;

comment on function public.resolver_link_documento(text) is
  'Resolve o slug da rota /biblioteca/l/[slug]: confere sessao, espaco, expiracao e revogacao, conta o acesso e devolve apenas a versao apontada. E security definer porque o portador do link nao tem papel na pasta e nenhuma policy o alcancaria; por isso mesmo ela nao passa por private.pode_ver_documento, de proposito, e por isso toda regra de acesso precisa ser conferida aqui dentro: nunca resolve documento sigiloso nem documento em pasta com nivel_acesso_maximo sigiloso, e so devolve storage_path quando documento_links.permite_download e verdadeiro. Molde do ShareLink do Paperless-ngx com a exigencia de sessao da casa.';

revoke all on function public.enviar_para_lixeira(uuid)          from public, anon;
revoke all on function public.restaurar_documento(uuid)          from public, anon;
revoke all on function public.definir_versao_primaria(uuid)      from public, anon;
revoke all on function public.eliminar_documento(uuid, text)     from public, anon;
revoke all on function public.resolver_link_documento(text)      from public, anon;
grant execute on function public.enviar_para_lixeira(uuid)       to authenticated;
grant execute on function public.restaurar_documento(uuid)       to authenticated;
grant execute on function public.definir_versao_primaria(uuid)   to authenticated;
grant execute on function public.eliminar_documento(uuid, text)  to authenticated;
grant execute on function public.resolver_link_documento(text)   to authenticated;

-- ------------------------------------------------------------
-- 18. RLS: ligado na mesma migracao que cria a tabela, sem excecao
-- ------------------------------------------------------------

alter table public.pastas             enable row level security;
alter table public.tipos_documentais  enable row level security;
alter table public.hipoteses_legais   enable row level security;
alter table public.documentos         enable row level security;
alter table public.documento_versoes  enable row level security;
alter table public.pasta_permissoes   enable row level security;
alter table public.documento_links    enable row level security;
alter table public.modelos_documento  enable row level security;

-- ---------- pastas ----------
drop policy if exists pastas_select_leitor on public.pastas;
create policy pastas_select_leitor on public.pastas for select to authenticated
  using ((select private.papel_na_pasta(id)) is not null);

drop policy if exists pastas_insert_editor on public.pastas;
create policy pastas_insert_editor on public.pastas for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and criado_por = (select auth.uid())
    and (
      (raiz = false
       and parent_id is not null
       and (select private.papel_na_pasta(parent_id)) in ('editor', 'revisor'))
      or (select public.autorizar('operacao.administrar'::public.permissao, null::uuid))
    )
  );

drop policy if exists pastas_update_editor on public.pastas;
create policy pastas_update_editor on public.pastas for update to authenticated
  using ((select private.papel_na_pasta(id)) in ('editor', 'revisor'))
  with check ((select private.papel_na_pasta(id)) in ('editor', 'revisor'));

-- Unica policy de delete desta parte, na lista fechada da convencao:
-- revisor, pasta vazia e nao raiz.
drop policy if exists pastas_delete_revisor on public.pastas;
create policy pastas_delete_revisor on public.pastas for delete to authenticated
  using (
    (select private.papel_na_pasta(id)) = 'revisor'
    and raiz = false
    and (select private.pasta_vazia(id))
  );

-- ---------- tipos_documentais ----------
drop policy if exists tipos_documentais_select_membro on public.tipos_documentais;
create policy tipos_documentais_select_membro on public.tipos_documentais for select to authenticated
  using ((select private.pertence_ao_espaco(workspace_id)));

drop policy if exists tipos_documentais_insert_administrador on public.tipos_documentais;
create policy tipos_documentais_insert_administrador on public.tipos_documentais for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
    and (select private.exige_aal2())
  );

drop policy if exists tipos_documentais_update_administrador on public.tipos_documentais;
create policy tipos_documentais_update_administrador on public.tipos_documentais for update to authenticated
  using ((select public.autorizar('documento.classificar'::public.permissao, null::uuid)))
  with check (
    (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
    and (select private.exige_aal2())
  );

-- ---------- hipoteses_legais ----------
drop policy if exists hipoteses_legais_select_membro on public.hipoteses_legais;
create policy hipoteses_legais_select_membro on public.hipoteses_legais for select to authenticated
  using ((select private.pertence_ao_espaco(workspace_id)));

drop policy if exists hipoteses_legais_insert_administrador on public.hipoteses_legais;
create policy hipoteses_legais_insert_administrador on public.hipoteses_legais for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
    and (select private.exige_aal2())
  );

drop policy if exists hipoteses_legais_update_administrador on public.hipoteses_legais;
create policy hipoteses_legais_update_administrador on public.hipoteses_legais for update to authenticated
  using ((select public.autorizar('documento.classificar'::public.permissao, null::uuid)))
  with check (
    (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
    and (select private.exige_aal2())
  );

-- ---------- documentos ----------
-- Regra da minuta do SEI: minuta nao tramita e nao se publica, e tambem nao se
-- le. Como o seed concede contribuidor a todo o setor e leitor a Diretoria,
-- sem esta clausula qualquer rascunho ficaria visivel ao setor inteiro desde o
-- primeiro salvamento, o que esvaziaria a hipotese documento_preparatorio_minuta
-- do vocabulario de hipoteses_legais. A ampliacao da leitura de minuta para o
-- aprovador designado entra em migracao posterior, depois da parte de
-- autorizacao, que e onde a designacao passa a existir.
drop policy if exists documentos_select_permitido on public.documentos;
create policy documentos_select_permitido on public.documentos for select to authenticated
  using (
    (select private.pode_ver_documento(id))
    and (status <> 'erased' or (select private.papel_no_documento(id)) = 'revisor')
    and (
      status <> 'draft'
      or criado_por = (select auth.uid())
      or (select private.tem_credencial_nominal(id))
      or (select public.autorizar('operacao.administrar'::public.permissao, null::uuid))
    )
  );

drop policy if exists documentos_insert_contribuidor on public.documentos;
create policy documentos_insert_contribuidor on public.documentos for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and criado_por = (select auth.uid())
    and status = 'draft'
    and lixeira_em is null
    and eliminado_em is null
    and (select private.papel_na_pasta(pasta_id))
        in ('contribuidor', 'editor', 'revisor')
    and (nivel_acesso <> 'sigiloso' or (select private.exige_aal2()))
  );

drop policy if exists documentos_update_autor_minuta on public.documentos;
create policy documentos_update_autor_minuta on public.documentos for update to authenticated
  using (
    (select private.papel_no_documento(id)) = 'contribuidor'
    and criado_por = (select auth.uid())
    and status = 'draft'
  )
  with check (
    (select private.papel_no_documento(id)) = 'contribuidor'
    and criado_por = (select auth.uid())
    and status = 'draft'
  );

drop policy if exists documentos_update_editor on public.documentos;
create policy documentos_update_editor on public.documentos for update to authenticated
  using ((select private.papel_no_documento(id)) = 'editor')
  with check ((select private.papel_no_documento(id)) = 'editor');

-- Revisor e quem muda nivel de acesso, hipotese legal, estado, lixeira e
-- eliminacao: por isso a escrita dele exige aal2 no with check, como a
-- convencao pede para toda escrita de decisao. Sobre documento sigiloso o
-- revisor da pasta produtora e reconhecido por private.pode_classificar_documento,
-- e nao por private.papel_no_documento, para que ele reclassifique sem ganhar
-- leitura do binario nem do texto_extraido.
drop policy if exists documentos_update_revisor on public.documentos;
create policy documentos_update_revisor on public.documentos for update to authenticated
  using (
    (select private.papel_no_documento(id)) = 'revisor'
    or (select private.pode_classificar_documento(id))
  )
  with check (
    (
      (select private.papel_no_documento(id)) = 'revisor'
      or (select private.pode_classificar_documento(id))
    )
    and (select private.exige_aal2())
  );

-- ---------- documento_versoes ----------
drop policy if exists documento_versoes_select_permitido on public.documento_versoes;
create policy documento_versoes_select_permitido on public.documento_versoes for select to authenticated
  using ((select private.pode_ver_documento(documento_id)));

-- O papel local contribuidor so versiona o que ele mesmo criou. Sem esta
-- clausula, qualquer voluntario com contribuidor na pasta do setor subiria
-- versao nova sobre a ata, o termo ou o procedimento de outra pessoa, e
-- documento_versoes_numera ainda marcaria essa versao como primaria quando nao
-- houvesse outra, apagando na pratica a distincao entre contribuidor e editor.
drop policy if exists documento_versoes_insert_contribuidor on public.documento_versoes;
create policy documento_versoes_insert_contribuidor on public.documento_versoes for insert to authenticated
  with check (
    enviado_por = (select auth.uid())
    and eliminada_em is null
    and (
      (select private.papel_no_documento(documento_id)) in ('editor', 'revisor')
      or (
        (select private.papel_no_documento(documento_id)) = 'contribuidor'
        and (select private.documento_autor(documento_id)) = (select auth.uid())
      )
    )
  );

drop policy if exists documento_versoes_update_editor on public.documento_versoes;
create policy documento_versoes_update_editor on public.documento_versoes for update to authenticated
  using ((select private.papel_no_documento(documento_id)) in ('editor', 'revisor'))
  with check ((select private.papel_no_documento(documento_id)) in ('editor', 'revisor'));

-- ---------- pasta_permissoes ----------
drop policy if exists pasta_permissoes_select_alcancado on public.pasta_permissoes;
create policy pasta_permissoes_select_alcancado on public.pasta_permissoes for select to authenticated
  using (
    (select private.papel_na_pasta(pasta_id)) is not null
    and (
      documento_id is null
      or (select private.pode_ver_documento(documento_id))
      -- Quem concede credencial nominal precisa enxergar as credenciais que
      -- concedeu, mesmo sobre documento sigiloso que nao pode abrir.
      or (select private.pode_classificar_documento(documento_id))
    )
  );

drop policy if exists pasta_permissoes_insert_revisor on public.pasta_permissoes;
create policy pasta_permissoes_insert_revisor on public.pasta_permissoes for insert to authenticated
  with check (
    concedido_por = (select auth.uid())
    and (
      (documento_id is null
       and (select private.papel_na_pasta(pasta_id)) = 'revisor')
      -- Concessao de credencial nominal de documento, inclusive sigiloso, e
      -- competencia do revisor da pasta produtora e exige segundo fator.
      or (documento_id is not null
          and (select private.pode_classificar_documento(documento_id))
          and (select private.exige_aal2()))
    )
  );

drop policy if exists pasta_permissoes_update_revisor on public.pasta_permissoes;
create policy pasta_permissoes_update_revisor on public.pasta_permissoes for update to authenticated
  using (
    (documento_id is null and (select private.papel_na_pasta(pasta_id)) = 'revisor')
    or (documento_id is not null and (select private.pode_classificar_documento(documento_id)))
  )
  with check (
    (documento_id is null and (select private.papel_na_pasta(pasta_id)) = 'revisor')
    or (documento_id is not null
        and (select private.pode_classificar_documento(documento_id))
        and (select private.exige_aal2()))
  );

-- ---------- documento_links ----------
drop policy if exists documento_links_select_emissor on public.documento_links;
create policy documento_links_select_emissor on public.documento_links for select to authenticated
  using (
    criado_por = (select auth.uid())
    or (select private.papel_no_documento(documento_id)) in ('editor', 'revisor')
  );

drop policy if exists documento_links_insert_editor on public.documento_links;
create policy documento_links_insert_editor on public.documento_links for insert to authenticated
  with check (
    criado_por = (select auth.uid())
    and revogado_em is null
    and acessos = 0
    and (select private.papel_no_documento(documento_id)) in ('editor', 'revisor')
  );

drop policy if exists documento_links_update_emissor on public.documento_links;
create policy documento_links_update_emissor on public.documento_links for update to authenticated
  using (
    criado_por = (select auth.uid())
    or (select private.papel_no_documento(documento_id)) = 'revisor'
  )
  with check (
    criado_por = (select auth.uid())
    or (select private.papel_no_documento(documento_id)) = 'revisor'
  );

-- ---------- modelos_documento ----------
drop policy if exists modelos_documento_select_aprovado on public.modelos_documento;
create policy modelos_documento_select_aprovado on public.modelos_documento for select to authenticated
  using (
    (select private.pertence_ao_espaco(workspace_id))
    and (
      status = 'approved'
      or criado_por = (select auth.uid())
      or (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
      or (select public.autorizar('trilha.ler_completa'::public.permissao, null::uuid))
    )
  );

drop policy if exists modelos_documento_insert_revisor on public.modelos_documento;
create policy modelos_documento_insert_revisor on public.modelos_documento for insert to authenticated
  with check (
    (select private.pertence_ao_espaco(workspace_id))
    and criado_por = (select auth.uid())
    and status in ('draft', 'legal_review')
    and (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
  );

-- Aprovar modelo e escrita de decisao: exige aal2 e parecer com autor e data.
drop policy if exists modelos_documento_update_revisor on public.modelos_documento;
create policy modelos_documento_update_revisor on public.modelos_documento for update to authenticated
  using ((select public.autorizar('documento.classificar'::public.permissao, null::uuid)))
  with check (
    (select public.autorizar('documento.classificar'::public.permissao, null::uuid))
    and (
      status <> 'approved'
      or ((select private.exige_aal2())
          and revisado_por is not null
          and revisado_em is not null)
    )
  );

-- ------------------------------------------------------------
-- 19. GRANTs explicitos, so as operacoes que tem policy
--     A intranet nao repete o grant em bloco da Redacao; anon nunca recebe
--     privilegio, e a rota publica de verificacao le por funcao security
--     definer de retorno fixo, que e da parte de autorizacao.
-- ------------------------------------------------------------

revoke all on public.pastas             from public, anon;
revoke all on public.tipos_documentais  from public, anon;
revoke all on public.hipoteses_legais   from public, anon;
revoke all on public.documentos         from public, anon;
revoke all on public.documento_versoes  from public, anon;
revoke all on public.pasta_permissoes   from public, anon;
revoke all on public.documento_links    from public, anon;
revoke all on public.modelos_documento  from public, anon;

grant select, insert, update, delete on public.pastas            to authenticated;
grant select, insert, update          on public.tipos_documentais to authenticated;
grant select, insert, update          on public.hipoteses_legais  to authenticated;
grant select, insert, update          on public.documentos        to authenticated;
grant select, insert, update          on public.documento_versoes to authenticated;
grant select, insert, update          on public.pasta_permissoes  to authenticated;
grant select, insert, update          on public.documento_links   to authenticated;
grant select, insert, update          on public.modelos_documento to authenticated;

-- ------------------------------------------------------------
-- 20. Chaves estrangeiras adiadas da parte base para documentos
--     Fechariam ciclo entre as partes, por isso entram aqui, depois das duas
--     tabelas, e so quando a coluna existe e a constraint ainda nao.
-- ------------------------------------------------------------

do $$
declare
  r record;
begin
  for r in
    select * from (values
      ('formacoes',                'comprovante_documento_id', 'formacoes_comprovante_documento_fk'),
      ('credenciais',              'documento_id',             'credenciais_documento_fk'),
      ('termos_adesao',            'documento_id',             'termos_adesao_documento_fk'),
      ('decisoes_institucionais',  'documento_anexo_id',       'decisoes_institucionais_documento_fk'),
      ('consentimentos',           'comprovante_documento_id', 'consentimentos_comprovante_documento_fk')
    ) as t(tabela, coluna, nome)
  loop
    if to_regclass('public.' || r.tabela) is not null
       and exists (select 1 from information_schema.columns c
                    where c.table_schema = 'public'
                      and c.table_name = r.tabela
                      and c.column_name = r.coluna)
       and not exists (select 1 from pg_constraint pc where pc.conname = r.nome)
    then
      execute format(
        'alter table public.%I add constraint %I foreign key (%I) references public.documentos (id) on delete set null',
        r.tabela, r.nome, r.coluna);
    end if;
  end loop;
end $$;

-- ------------------------------------------------------------
-- 21. Seed do vocabulario, dos tipos documentais e da arvore de pastas
--     Idempotente e sem dado pessoal. Nomes de coordenacao vem de setores.
-- ------------------------------------------------------------

do $$
declare
  v_ws       uuid;
  v_inst     uuid;
  v_setores  uuid;
  v_pessoas  uuid;
  v_raiz     uuid;
  v_nivel    text;
  s          record;
  sub        text;
begin
  select id into v_ws from public.workspaces where slug = 'producao' limit 1;
  if v_ws is null then
    return;
  end if;

  -- Hipoteses legais, vocabulario controlado do SEI.
  insert into public.hipoteses_legais (workspace_id, codigo, nome, descricao, exige_dado_sensivel)
  values
    (v_ws, 'dados_pessoais_lgpd_art7', 'Dados pessoais, LGPD art. 7',
     'Documento com dado pessoal comum, restrito por padrao como no SEI e no SUAP.', false),
    (v_ws, 'dados_sensiveis_lgpd_art11', 'Dados sensiveis, LGPD art. 11',
     'Documento com dado de saude ou outro dado sensivel. Obrigatorio na pasta do setor Saude; legitimo interesse nao se aplica.', true),
    (v_ws, 'documento_preparatorio_minuta', 'Documento preparatorio, minuta',
     'Minuta ainda em elaboracao, que pela regra do SEI nao tramita, nao se publica e so e legivel pelo autor, por quem tem credencial nominal e pelo administrador.', false),
    (v_ws, 'sigilo_profissional', 'Sigilo profissional',
     'Documento coberto por sigilo profissional de quem o produziu.', false),
    (v_ws, 'seguranca_operacional_grd', 'Seguranca operacional de GRD',
     'Documento cuja divulgacao compromete operacao de gestao de risco e desastres.', false),
    (v_ws, 'deliberacao_diretoria_em_curso', 'Deliberacao da Diretoria em curso',
     'Documento de deliberacao ainda nao concluida pela Junta ou pela Diretoria.', false)
  on conflict on constraint hipoteses_legais_codigo_unico do nothing;

  -- Tipos documentais com temporalidade. So nascem com prazo fixado os tipos
  -- em que a norma ja fixou o prazo: prestacao de contas, pelo art. 68 do
  -- MROSC, e as tres atas, por guarda permanente do Estatuto. Nos demais,
  -- prazo_pendente_decisao continua verdadeiro, prazo_guarda_anos fica nulo e
  -- a base legal cita apenas a norma que existe, porque a decisao D27 registra
  -- que o prazo ainda nao esta fixado.
  insert into public.tipos_documentais (
    workspace_id, tipo_ato, nome, orgao, metadados_obrigatorios, nivel_acesso_padrao,
    contem_dados_pessoais, base_legal, prazo_guarda_anos, guarda_permanente,
    prazo_pendente_decisao, prazo_envio_dias, destinatarios_automaticos,
    dias_na_lixeira, pode_eliminar_antes_do_prazo
  ) values
    (v_ws, 'ata_junta', 'Ata de reuniao da Junta de Governo', 'junta_de_governo',
     '{"required":["numero","data_reuniao","presentes","pauta","data_referencia"]}', 'restrito', true,
     'LGPD art. 7, II, e Estatuto da CVB art. 33, paragrafos 1 e 3', null, true,
     false, 15, '{membros_junta}', 30, false),
    (v_ws, 'ata_assembleia', 'Ata de assembleia', 'assembleia',
     '{"required":["numero","data_reuniao","presentes","pauta","data_referencia"]}', 'restrito', true,
     'LGPD art. 7, II, e Estatuto da CVB art. 90', null, true,
     false, null, '{diretoria}', 30, false),
    (v_ws, 'ata_diretoria', 'Ata de reuniao da Diretoria', 'diretoria',
     '{"required":["numero","data_reuniao","presentes","pauta","data_referencia"]}', 'restrito', true,
     'LGPD art. 7, II, e Estatuto da CVB art. 90', null, true,
     false, null, '{diretoria}', 30, false),
    (v_ws, 'termo_adesao', 'Termo de adesao ao servico voluntario', 'pessoa',
     '{"required":["pessoa","data_inicio","atividade","setor","modelo_versao"]}', 'restrito', true,
     'LGPD art. 7, II e V, e Lei 9.608/1998 art. 2', null, false,
     true, null, '{secretaria}', 30, true),
    (v_ws, 'termo_desligamento', 'Termo de desligamento', 'pessoa',
     '{"required":["pessoa","data_fim","motivo"]}', 'restrito', true,
     'LGPD art. 7, II, e Lei 9.608/1998', null, false,
     true, null, '{secretaria}', 30, true),
    (v_ws, 'consentimento_lgpd', 'Consentimento de tratamento de dados', 'pessoa',
     '{"required":["pessoa","finalidade","versao_politica"]}', 'restrito', true,
     'LGPD art. 8, paragrafo 6, prova do consentimento', null, false,
     true, null, '{secretaria}', 30, true),
    (v_ws, 'autorizacao_imagem', 'Autorizacao de uso de imagem', 'pessoa',
     '{"required":["pessoa","finalidade","vigencia_inicio","menor_de_idade"]}', 'restrito', true,
     'LGPD art. 7, I, e Codigo Civil art. 20', null, false,
     true, null, '{comunicacao}', 30, true),
    (v_ws, 'certificado', 'Certificado de curso ou atividade', 'pessoa',
     '{"required":["pessoa","atividade","carga_horaria","codigo_verificacao","data_referencia"]}', 'restrito', true,
     'LGPD art. 7, V, execucao de contrato', null, false,
     true, null, '{}', 30, true),
    (v_ws, 'politica', 'Politica institucional', 'diretoria',
     '{"required":["numero","vigencia_inicio","revisao_em","aprovado_por"]}', 'publico', false,
     'LGPD art. 37, registro das operacoes, e prestacao de contas institucional', null, true,
     false, null, '{}', 30, false),
    (v_ws, 'procedimento', 'Procedimento operacional', 'coordenacao',
     '{"required":["setor","numero","vigencia_inicio","revisao_em"]}', 'publico', false,
     'Documento operacional sem dado pessoal', null, false,
     true, null, '{}', 30, true),
    (v_ws, 'oficio', 'Oficio', 'diretoria',
     '{"required":["destinatario","assunto","data_referencia"]}', 'restrito', false,
     'LGPD art. 7, II, quando houver obrigacao legal', null, false,
     true, null, '{}', 30, true),
    (v_ws, 'parecer', 'Parecer', 'revisao_de_contas',
     '{"required":["assunto","autor","data_referencia"]}', 'restrito', false,
     'LGPD art. 7, II', null, false,
     true, null, '{diretoria}', 30, true),
    (v_ws, 'relatorio', 'Relatorio de atividade', 'coordenacao',
     '{"required":["setor","periodo","autor"]}', 'publico', false,
     'Documento institucional sem dado pessoal', null, false,
     true, null, '{}', 30, true),
    (v_ws, 'prestacao_contas', 'Prestacao de contas', 'diretoria',
     '{"required":["parceria","periodo","valor","orgao_destinatario","data_referencia"]}', 'restrito', false,
     'MROSC, Lei 13.019/2014 art. 68, dez anos apos a apresentacao', 10, false,
     false, null, '{diretoria}', 30, false)
  on conflict on constraint tipos_documentais_tipo_ato_unico do nothing;

  -- Raizes da arvore. Criadas por seed, nao podem ser movidas nem apagadas.
  insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, raiz, descricao)
  values (v_ws, null, 'Institucional', 'institucional', null, true,
          'Atas, estatuto e regimentos, politicas, prestacao de contas e oficios da filial.')
  on conflict on constraint pastas_workspace_path_unico do nothing;
  select id into v_inst from public.pastas where workspace_id = v_ws and path = '/institucional';

  foreach sub in array array['atas', 'estatuto-e-regimentos', 'politicas',
                             'prestacao-de-contas', 'oficios'] loop
    insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, raiz)
    values (v_ws, v_inst, initcap(replace(sub, '-', ' ')), sub, null, true)
    on conflict on constraint pastas_workspace_path_unico do nothing;
  end loop;

  insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, raiz, descricao)
  values (v_ws, null, 'Setores', 'setores', null, true,
          'Uma pasta por coordenacao, com procedimentos, relatorios e formularios.')
  on conflict on constraint pastas_workspace_path_unico do nothing;
  select id into v_setores from public.pastas where workspace_id = v_ws and path = '/setores';

  for s in
    select st.id, st.slug, st.nome, st.restrito_por_padrao
      from public.setores st
     where st.workspace_id = v_ws and st.ativo
  loop
    -- A pasta do setor marcado como restrito_por_padrao, hoje a Saude, nasce
    -- restrita de verdade, e nao apenas como criterio de aceite: a coluna
    -- setores.restrito_por_padrao passa a ter leitor no modelo.
    v_nivel := case when s.restrito_por_padrao then 'restrito' else 'publico' end;

    insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, raiz, nivel_acesso_maximo)
    values (v_ws, v_setores, s.nome, s.slug, s.id, true, v_nivel)
    on conflict on constraint pastas_workspace_path_unico do nothing;
    select id into v_raiz
      from public.pastas where workspace_id = v_ws and path = '/setores/' || s.slug;

    foreach sub in array array['procedimentos', 'relatorios', 'formularios'] loop
      insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, raiz, nivel_acesso_maximo)
      values (v_ws, v_raiz, initcap(sub), sub, s.id, true, v_nivel)
      on conflict on constraint pastas_workspace_path_unico do nothing;
    end loop;

    -- Coordenador do setor e revisor da pasta do setor; membros do setor
    -- contribuem; Diretoria le. Papeis locais do rolemap.xml do Plone.
    insert into public.pasta_permissoes
      (workspace_id, pasta_id, sujeito_tipo, sujeito_papel, papel_local, efeito, motivo)
    values (v_ws, v_raiz, 'papel', 'coordenador', 'revisor', 'permitir',
            'Dono da pasta do setor, conforme a matriz de papeis do escopo.')
    on conflict do nothing;
    insert into public.pasta_permissoes
      (workspace_id, pasta_id, sujeito_tipo, sujeito_setor_id, papel_local, efeito, motivo)
    values (v_ws, v_raiz, 'setor', s.id, 'contribuidor', 'permitir',
            'Membros do setor enviam documentos para a propria pasta.')
    on conflict do nothing;
    insert into public.pasta_permissoes
      (workspace_id, pasta_id, sujeito_tipo, sujeito_papel, papel_local, efeito, motivo)
    values (v_ws, v_raiz, 'papel', 'diretoria', 'leitor', 'permitir',
            'Diretoria le as pastas de todos os setores.')
    on conflict do nothing;
  end loop;

  insert into public.pastas (workspace_id, parent_id, nome, slug, setor_id, raiz, descricao, nivel_acesso_maximo)
  values (v_ws, null, 'Pessoas', 'pessoas', null, true,
          'Documentos de vinculo por pessoa, criados sob demanda pelo tramite. Restrito por padrao.',
          'restrito')
  on conflict on constraint pastas_workspace_path_unico do nothing;
  select id into v_pessoas from public.pastas where workspace_id = v_ws and path = '/pessoas';

  -- Permissoes das raizes institucionais.
  insert into public.pasta_permissoes
    (workspace_id, pasta_id, sujeito_tipo, sujeito_papel, papel_local, efeito, motivo)
  values
    (v_ws, v_inst,    'papel', 'diretoria',  'revisor', 'permitir', 'Diretoria e dona da pasta institucional.'),
    (v_ws, v_inst,    'papel', 'secretaria', 'editor',  'permitir', 'Secretaria recebe e organiza atas e termos.'),
    (v_ws, v_pessoas, 'papel', 'secretaria', 'revisor', 'permitir', 'Secretaria e dona das pastas de cadastro e termos.'),
    (v_ws, v_setores, 'papel', 'diretoria',  'leitor',  'permitir', 'Diretoria le a arvore de setores.')
  on conflict do nothing;

  -- Politicas e procedimentos institucionais sao legiveis por toda a casa.
  insert into public.pasta_permissoes
    (workspace_id, pasta_id, sujeito_tipo, sujeito_papel, papel_local, efeito, motivo)
  select v_ws, p.id, 'papel', pa.slug, 'leitor', 'permitir',
         'Politica institucional publicada para toda a casa.'
    from public.pastas p
    cross join (values ('colaborador'), ('voluntario'), ('instrutor')) as pa(slug)
   where p.workspace_id = v_ws and p.path = '/institucional/politicas'
     and exists (select 1 from public.papeis q where q.slug = pa.slug)
  on conflict do nothing;
end $$;

-- ============================================================
-- 22. MIGRACAO PROPRIA, depois das tabelas das duas partes:
--     pendencias declaradas em comentario nas partes de base e de contato e
--     mural que nao tinham dono no modelo. Vai em arquivo separado, aplicado
--     depois desta parte e da parte de contato e mural, e nao faz nada
--     enquanto as tabelas do mural nao existirem.
-- ============================================================

create or replace function public.avisos_valida_anexos()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_faltando text;
begin
  if new.anexos is null or array_length(new.anexos, 1) is null then
    return new;
  end if;
  select a::text into v_faltando
    from unnest(new.anexos) as a
   where not exists (
     select 1 from public.documentos d
      where d.id = a::text::uuid
        and d.workspace_id = new.workspace_id
   )
   limit 1;
  if v_faltando is not null then
    raise exception 'anexo % nao e documento deste espaco', v_faltando;
  end if;
  return new;
end;
$$;

comment on function public.avisos_valida_anexos() is
  'Recusa aviso cujo array anexos aponte uuid que nao exista em public.documentos no mesmo workspace_id. A coluna avisos.anexos nasceu como ponteiro solto para a biblioteca, sem chave estrangeira possivel por ser array, e a validacao estava declarada como pendencia na parte de contato e mural, sem dono no modelo.';

do $$
begin
  if to_regclass('public.avisos') is not null then
    execute 'drop trigger if exists avisos_valida_anexos on public.avisos';
    execute 'create trigger avisos_valida_anexos
               before insert or update of anexos on public.avisos
               for each row execute function public.avisos_valida_anexos()';
  end if;
end $$;

-- Comentario de documento: o alcance passa a ser o do proprio documento, e nao
-- o do grupo. Sem esta troca, quem esta no grupo comentava em documento que
-- nao alcanca, e quem alcanca o documento por credencial nominal nao via o
-- comentario. Pendencia declarada na parte de contato e mural.
do $$
begin
  if to_regclass('public.comentarios') is not null then
    execute 'drop policy if exists comentarios_select_alvo on public.comentarios';
    execute 'create policy comentarios_select_alvo on public.comentarios for select to authenticated
               using (
                 (select private.pertence_ao_espaco(workspace_id))
                 and (
                   (entidade_tipo = ''aviso'' and (select private.aviso_visivel(entidade_id)))
                   or (entidade_tipo = ''documento'' and (select private.pode_ver_documento(entidade_id)))
                 )
               )';
  end if;
end $$;



-- ============================================================
-- 30. Autorização de documentos, assinatura e trilha de auditoria
-- ============================================================

-- ============================================================================
-- Intranet CVB-RJ, parte 4: autorizacao de documentos, assinatura e trilha.
--
-- Padroes transpostos (nomes de tabela, coluna, estado e regra; nenhum trecho
-- de codigo GPL ou AGPL foi copiado):
--   Jorvik (Croce Rossa Italiana) ....... Autorizzazione: richiedente, concessa,
--                                         motivo_negazione, oggetto_tipo/oggetto_id,
--                                         progressivo (aqui `rodada`), scadenza,
--                                         tipo_gestione, automatica; Delega para
--                                         a delegacao por ausencia.
--   Nextcloud Approval .................. approval_rules, approval_rule_requesters,
--                                         approval_rule_approvers, approval_activity,
--                                         unapprove_when_modified e a recusa de
--                                         decidir arquivo alterado (OutdatedEtagException).
--   XWiki Publication Workflow .......... maquina de estados do documento
--                                         (draft, moderating, validating, valid,
--                                         published, archived) com transicao guardada.
--   Mayan EDMS .......................... WorkflowStateEscalation para prazo,
--                                         lembrete e escalonamento.
--   SEI ................................. minuta nao tramita, bloco de assinatura,
--                                         nivel de acesso com hipotese legal.
--   Documenso ........................... DocumentAuditLog como catalogo de estados
--                                         e evidencias por documento.
--   DRK Rundlaufbeschluesse (abstimmung)  hash de IP e de agente na trilha; snapshot
--                                         de votantes elegiveis na abertura.
--   Papermark ........................... versao com hash e versao primaria (a parte
--                                         da biblioteca cria as tabelas).
--   HumHub, Open Social, Plone ........... papeis locais e visibilidade (partes 2 e 3).
--   Exemplo oficial slack-clone da Supabase  authorize()/app_permission, aqui
--                                         public.autorizar(permissao, setor).
--   docs/04-rastreabilidade-blockchain.md, secao 6: cadeia de hashes com
--   pg_advisory_xact_lock por fluxo, append-only por RLS mais trigger, verificador
--   e ancora diaria. Nenhum dado pessoal entra em auditoria, ancoras ou pagina publica.
--
-- Migracao so acrescenta. Nada da Redacao e removido ou renomeado.
-- ============================================================================

create schema if not exists auditoria;
create schema if not exists lgpd;

comment on schema auditoria is 'Trilha append-only unificada, catalogo de fluxos neutros, verificador e ancoras. Desenho de docs/04-rastreabilidade-blockchain.md, secao 6.';
comment on schema lgpd is 'Registro do art. 37 da LGPD no modelo simplificado da Resolucao CD/ANPD 2/2022, pedidos de titular (art. 18) e incidentes (Resolucao CD/ANPD 15/2024).';

revoke all on schema auditoria from public, anon;
revoke all on schema lgpd      from public, anon;
-- service_role tambem recebe usage: e a role da rota do cron e da chave de
-- servico (D39), e sem ela auditoria.listar_ancoras, lgpd.abrir_pedido_titular e
-- lgpd.consultar_pedido_titular nao sao nem resolviveis por quem as executa.
grant usage on schema auditoria to authenticated, service_role;
grant usage on schema lgpd      to authenticated, service_role;

-- ============================================================================
-- 1. Funcoes utilitarias de hash e de prazo
-- ============================================================================

-- sha256() e gen_random_uuid() sao do pg_catalog no Postgres 17: nenhuma
-- extensao e necessaria e o search_path vazio continua valendo.
create or replace function public.hash_canonico(p_documento jsonb)
returns text language sql immutable set search_path = '' as $$
  select encode(sha256(convert_to(p_documento::text, 'UTF8')), 'hex');
$$;

comment on function public.hash_canonico(jsonb) is 'SHA-256 do JSON canonico (o jsonb do Postgres ja ordena as chaves de forma deterministica). E o hash_decisao gravado em autorizacao_decisoes e na cadeia, no padrao do hash de decisao do DRK Rundlaufbeschluesse.';

create or replace function public.hash_curto(p_texto text)
returns text language sql immutable set search_path = '' as $$
  select case
    when p_texto is null or btrim(p_texto) = '' then null
    else left(encode(sha256(convert_to(p_texto, 'UTF8')), 'hex'), 32)
  end;
$$;

comment on function public.hash_curto(text) is 'SHA-256 truncado a 32 hexadecimais, usado em ip_hash e user_agent_hash. Copia o ipHash de rundlauf-app/lib/audit.ts do DRK: a trilha guarda o hash, o endereco em claro fica so nas tabelas apagaveis.';

create or replace function public.gerar_codigo_verificacao()
returns text language plpgsql volatile set search_path = '' as $$
declare
  -- Base32 de Crockford, sem I, L, O e U: nao ha como confundir letra com digito
  -- ao ler o codigo impresso no PDF ou no QR.
  v_alfabeto constant text := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  -- 16 bytes de CSPRNG: 128 bits inteiros. gen_random_uuid() daria 122, porque
  -- quatro bits sao de versao e dois de variante, e o escopo, o comentario desta
  -- funcao e as colunas codigo_verificacao afirmam 128.
  v_bytes    bytea := extensions.gen_random_bytes(16);
  v_codigo   text := '';
  v_valor    integer;
  v_bit      integer;
  i          integer;
  j          integer;
begin
  for i in 0..25 loop
    v_valor := 0;
    for j in 0..4 loop
      v_bit := i * 5 + j;
      if v_bit < 128 then
        v_valor := v_valor * 2 + ((get_byte(v_bytes, v_bit / 8) >> (7 - (v_bit % 8))) & 1);
      else
        v_valor := v_valor * 2;
      end if;
    end loop;
    v_codigo := v_codigo || substr(v_alfabeto, v_valor + 1, 1);
  end loop;
  return v_codigo;
end;
$$;

comment on function public.gerar_codigo_verificacao() is 'Codigo de 128 bits vindos de extensions.gen_random_bytes(16), em base32 de Crockford, 26 caracteres, credencial da pagina publica /verificar/[codigo]. Molde do /validar/[token] do Curso de Puncao Venosa: sem login, alta entropia, sem enumeracao.';

create or replace function public.somar_dias_uteis(p_de timestamptz, p_dias integer)
returns timestamptz language plpgsql stable set search_path = '' as $$
declare
  v_data   timestamptz := coalesce(p_de, now());
  v_restam integer := greatest(coalesce(p_dias, 0), 0);
begin
  -- Premissa declarada: nao ha calendario de feriados nesta rodada; conta-se
  -- apenas segunda a sexta. Feriado entra como decisao posterior sem mudar schema.
  while v_restam > 0 loop
    v_data := v_data + interval '1 day';
    if extract(isodow from v_data) < 6 then
      v_restam := v_restam - 1;
    end if;
  end loop;
  return v_data;
end;
$$;

comment on function public.somar_dias_uteis(timestamptz, integer) is 'Prazo em dias uteis das etapas, no molde do amount/unit do WorkflowStateEscalation do Mayan. Sem calendario de feriados nesta rodada.';

revoke all on function public.hash_canonico(jsonb)                from public, anon;
revoke all on function public.hash_curto(text)                    from public, anon;
revoke all on function public.gerar_codigo_verificacao()          from public, anon;
revoke all on function public.somar_dias_uteis(timestamptz, integer) from public, anon;
grant execute on function public.hash_canonico(jsonb)                to authenticated;
grant execute on function public.hash_curto(text)                    to authenticated;
grant execute on function public.gerar_codigo_verificacao()          to authenticated;
grant execute on function public.somar_dias_uteis(timestamptz, integer) to authenticated;

-- ============================================================================
-- 2. auditoria.fluxos: catalogo neutro
-- ============================================================================

create table if not exists auditoria.fluxos (
  codigo        text primary key check (codigo ~ '^F[0-9]{2}$'),
  nome_interno  text not null,
  descricao     text,
  dado_sensivel boolean not null default false,
  ativo         boolean not null default true,
  criado_em     timestamptz not null default now()
);

comment on table auditoria.fluxos is 'Catalogo dos codigos neutros de fluxo (F01, F02). A cadeia e a pagina publica so conhecem o codigo: o nome de um fluxo de saude nunca sai do banco. Regra de docs/04, secao 6, e do Manual de Protecao de Dados em Acao Humanitaria do CICV (manter rotulo identificador fora da estrutura imutavel). Sem workspace_id: o catalogo e da instalacao.';
comment on column auditoria.fluxos.nome_interno is 'Nome legivel, visivel apenas a administrador e auditor; nunca vai a auditoria.eventos nem a /verificar.';
comment on column auditoria.fluxos.dado_sensivel is 'Marca fluxo do art. 11 da LGPD; nenhuma tela publica lista fluxo, e esta coluna reforca a proibicao no codigo.';

insert into auditoria.fluxos (codigo, nome_interno, descricao, dado_sensivel) values
  ('F01', 'autorizacao.documento', 'Tramite de documento com etapas encadeadas e homologacao.', false),
  ('F02', 'autorizacao.leve',      'Tramite leve sem arquivo (imagem, participacao, ressarcimento, acesso a pasta).', false),
  ('F03', 'assinatura',            'Aceite interno, assinatura gov.br e conferencia do validador do ITI.', false),
  ('F04', 'documento.versao',      'Versao, publicacao, download e eliminacao na biblioteca.', false),
  ('F05', 'mural.publicacao',      'Publicacao, aprovacao e confirmacao de leitura no mural.', false),
  ('F06', 'imagem.autorizacao',    'Concessao, revogacao e uso publicado de autorizacao de imagem.', false),
  ('F07', 'identidade.cadastro',   'Identidade, vinculo, papel, delegacao, convite e consentimento.', false),
  ('F08', 'saude.ficha',           'Dados de saude de voluntario; nunca aparece em pagina publica.', true),
  ('F09', 'editorial',             'Ponte do activity_log da Redacao ate a migracao de identidade.', false),
  ('F10', 'lgpd.titular',          'Exportacao, anonimizacao e pedidos do canal do titular.', false),
  ('F11', 'contato.diretorio',     'Consulta e exportacao do diretorio de contato.', false),
  ('F12', 'mural.relatorio_nominal', 'Exportacao nominal do relatorio de leitura do mural, com finalidade escrita.', false)
on conflict (codigo) do nothing;

alter table auditoria.fluxos enable row level security;

create policy fluxos_select_auditor on auditoria.fluxos for select to authenticated
  using (
    (select public.autorizar('trilha.ler_completa'::public.permissao, null))
    or (select public.autorizar('autorizacao.regrar'::public.permissao, null))
  );

revoke all on table auditoria.fluxos from public, anon;
grant select on table auditoria.fluxos to authenticated;

-- ============================================================================
-- 3. auditoria.eventos: trilha append-only com hash encadeado
-- ============================================================================

create table if not exists auditoria.eventos (
  seq             bigint generated always as identity primary key,
  ordem_no_fluxo  bigint not null,
  ocorrido_em     timestamptz not null default now(),
  workspace_id    uuid not null references public.workspaces (id),
  fluxo           text not null references auditoria.fluxos (codigo),
  entidade_tipo   text not null,
  entidade_id     uuid not null,
  versao          integer,
  ator_id         uuid,
  papel           text not null,
  acao            text not null check (acao in (
                    'identidade.criada','identidade.vinculada','identidade.mfa_removida',
                    'identidade.recuperacao_usada',
                    'vinculo.criado','vinculo.confirmado','vinculo.encerrado',
                    'papel.concedido','papel.revogado',
                    'delegacao.criada','delegacao.encerrada',
                    'consentimento.concedido','consentimento.revogado',
                    'convite.emitido','convite.aceito','convite.revogado',
                    'aviso.publicado','aviso.aprovado','aviso.devolvido',
                    'aviso.leitura_confirmada','aviso.copiado_whatsapp',
                    'aviso.relatorio_exportado',
                    'comentario.aprovado','comentario.ocultado',
                    'autorizacao.solicitada','autorizacao.etapa_aberta',
                    'autorizacao.lembrete_enviado','autorizacao.escalada','autorizacao.delegada',
                    'autorizacao.aprovada','autorizacao.homologada','autorizacao.devolvida',
                    'autorizacao.negada','autorizacao.retirada',
                    'autorizacao.aprovada_automaticamente','autorizacao.expirada',
                    'documento.versao_criada','documento.submetido','documento.aprovacao_invalidada',
                    'documento.publicado','documento.arquivado','documento.baixado',
                    'documento.nivel_alterado','documento.eliminado','documento.hash_divergente',
                    'assinatura.aceite_registrado','assinatura.pdf_gerado',
                    'assinatura.pdf_assinado_recebido','assinatura.hash_conferido',
                    'assinatura.hash_divergente','assinatura.validacao_registrada',
                    'imagem.autorizacao_concedida','imagem.autorizacao_revogada','imagem.uso_publicado',
                    'regra.criada','regra.alterada','regra.desativada',
                    'titular.exportado','titular.anonimizado',
                    'auditoria.verificacao_ok','auditoria.verificacao_falhou','auditoria.ancora_publicada'
                  )),
  antes           jsonb,
  depois          jsonb,
  hash_arquivo    text check (hash_arquivo    ~ '^[0-9a-f]{64}$'),
  hash_decisao    text check (hash_decisao    ~ '^[0-9a-f]{64}$'),
  ip_hash         text check (ip_hash         ~ '^[0-9a-f]{32}$'),
  user_agent_hash text check (user_agent_hash ~ '^[0-9a-f]{32}$'),
  hash_anterior   text not null check (hash_anterior ~ '^[0-9a-f]{64}$'),
  hash_linha      text not null check (hash_linha    ~ '^[0-9a-f]{64}$')
);

comment on table auditoria.eventos is 'Trilha append-only da intranet e da Redacao, com vocabulario entidade.evento e hash encadeado por fluxo. O Curso vive em outro projeto Supabase, sem rota de ingestao, sem papel de servico e sem codigo de fluxo proprio em auditoria.fluxos: os eventos dele entram por rota autenticada com papel de servico e codigo de fluxo proprio, sem dado pessoal, quando a Secretaria do Curso passar a autenticar pela intranet. Desenho de docs/04, secao 6, sobre o padrao publico de hash chain em PostgreSQL; vocabulario e recorte de campos do audit_log do DRK Rundlaufbeschluesse e do DocumentAuditLog do Documenso. Base legal da propria trilha: LGPD art. 37 combinado com art. 6, X.';
comment on column auditoria.eventos.seq is 'Chave primaria e unico bigint generated always as identity de public/auditoria junto de auditoria.verificacoes. Nao ordena mais a cadeia: quem ordena e ordem_no_fluxo.';
comment on column auditoria.eventos.ordem_no_fluxo is 'Contador proprio por fluxo, atribuido dentro de auditoria.encadear_evento() depois do pg_advisory_xact_lock, como sucessor do maior valor ja gravado naquele fluxo, e com indice unico por fluxo. Ordena a cadeia no lugar de seq porque seq e generated always as identity e e atribuido quando a tupla e montada, antes do trigger: duas transacoes concorrentes no mesmo fluxo podem encadear na ordem inversa e o verificador reportaria quebra onde nao houve adulteracao.';
comment on column auditoria.eventos.fluxo is 'Codigo neutro. O nome do fluxo nunca entra aqui.';
comment on column auditoria.eventos.acao is 'Vocabulario fechado no formato entidade.evento; a lista do check fica espelhada em lib/auditoria/acoes.ts, e valor novo entra por migracao que altera os dois lados.';
comment on column auditoria.eventos.ator_id is 'UUID de auth.users, de proposito SEM chave estrangeira: a anonimizacao do titular apaga a pessoa sem violar o append-only, deixando um UUID orfao, como manda docs/04, secao 5.';
comment on column auditoria.eventos.antes is 'Estado anterior, restrito a lista de campos permitidos (espelhada em lib/auditoria/campos-permitidos.ts). Nunca nome, e-mail, motivo ou conteudo.';
comment on column auditoria.eventos.depois is 'Estado posterior, mesma lista de campos permitidos.';
comment on column auditoria.eventos.ip_hash is 'SHA-256 do IP truncado a 32 hexadecimais. IP em claro so em autorizacao_decisoes, assinaturas e consentimentos, que sao apagaveis.';
comment on column auditoria.eventos.hash_linha is 'SHA-256 da concatenacao canonica da linha inteira mais hash_anterior, calculado por trigger BEFORE INSERT com pg_advisory_xact_lock por fluxo.';

create index if not exists eventos_fluxo_seq_idx     on auditoria.eventos (fluxo, seq desc);
create index if not exists eventos_entidade_idx      on auditoria.eventos (entidade_tipo, entidade_id, seq desc);
create index if not exists eventos_ator_id_idx       on auditoria.eventos (ator_id) where ator_id is not null;
create index if not exists eventos_workspace_id_ocorrido_em_idx on auditoria.eventos (workspace_id, ocorrido_em desc);
create unique index if not exists eventos_fluxo_ordem_no_fluxo_idx on auditoria.eventos (fluxo, ordem_no_fluxo);

-- Encadeamento: exatamente o que docs/04, secao 6, descreve.
create or replace function auditoria.encadear_evento()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_anterior text;
  v_ordem    bigint;
  v_chave    text;
begin
  -- Lista fechada de campos que podem viajar em antes/depois. O motivo da
  -- decisao fica em autorizacao_decisoes, que e apagavel; na cadeia entra so o hash.
  foreach v_chave in array array['antes','depois'] loop
    if (case when v_chave = 'antes' then new.antes else new.depois end) is not null then
      if jsonb_typeof(case when v_chave = 'antes' then new.antes else new.depois end) <> 'object' then
        raise exception 'auditoria.eventos.%: e preciso um objeto JSON.', v_chave using errcode = '22023';
      end if;
      if exists (
        select 1
        from jsonb_object_keys(case when v_chave = 'antes' then new.antes else new.depois end) as t(campo)
        where t.campo not in (
          'estado','etapa','etapa_atual','ordem','rodada','quorum','prazo_em',
          'acao_ao_expirar','tipo','tipo_ato','tipo_gestao','automatica','versao',
          'nivel_assinatura','nivel_acesso','status','hash_arquivo','hash_versao',
          'hash_decisao','hash_confere','resultado_validador',
          'autorizacao_id','etapa_id','regra_id','documento_id','versao_id','setor_id','pasta_id'
        )
      ) then
        raise exception 'auditoria.eventos.%: campo fora da lista permitida; dado pessoal nao entra na trilha.', v_chave
          using errcode = '42501';
      end if;
    end if;
  end loop;

  -- Serializa a cabeca da cadeia por fluxo, como recomendam os artigos de hash
  -- chain em PostgreSQL citados em docs/04, secao 3.
  perform pg_advisory_xact_lock(4270001, hashtext(new.fluxo));

  select e.hash_linha, e.ordem_no_fluxo into v_anterior, v_ordem
    from auditoria.eventos e
   where e.fluxo = new.fluxo
   order by e.ordem_no_fluxo desc
   limit 1;

  -- Contador proprio do fluxo, atribuido ja sob o lock: seq nao serve de ordem
  -- porque e atribuido antes do trigger e inverte com transacoes concorrentes.
  new.ordem_no_fluxo := coalesce(v_ordem, 0) + 1;
  new.hash_anterior := coalesce(v_anterior, repeat('0', 64));
  new.ocorrido_em   := coalesce(new.ocorrido_em, now());
  new.hash_linha    := encode(sha256(convert_to(concat_ws('|',
      new.seq::text,
      new.ordem_no_fluxo::text,
      to_char(new.ocorrido_em at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF'),
      new.workspace_id::text,
      new.fluxo,
      new.entidade_tipo,
      new.entidade_id::text,
      coalesce(new.versao::text, ''),
      coalesce(new.ator_id::text, ''),
      new.papel,
      new.acao,
      coalesce(new.antes::text, ''),
      coalesce(new.depois::text, ''),
      coalesce(new.hash_arquivo, ''),
      coalesce(new.hash_decisao, ''),
      coalesce(new.ip_hash, ''),
      coalesce(new.user_agent_hash, ''),
      new.hash_anterior
    ), 'UTF8')), 'hex');

  return new;
end;
$$;

comment on function auditoria.encadear_evento() is 'Trigger BEFORE INSERT que valida a lista de campos permitidos, toma pg_advisory_xact_lock por fluxo, le a cabeca da cadeia, atribui ordem_no_fluxo e calcula hash_anterior e hash_linha. Implementa docs/04, secao 6, sem nenhuma extensao alem do sha256 nativo do Postgres 17.';

drop trigger if exists eventos_encadeia on auditoria.eventos;
create trigger eventos_encadeia
  before insert on auditoria.eventos
  for each row execute function auditoria.encadear_evento();

-- Append-only de verdade: nem service_role edita.
create or replace function auditoria.recusar_alteracao()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  raise exception 'auditoria.% e append-only: update e delete sao proibidos para qualquer role.', tg_table_name
    using errcode = '42501';
end;
$$;

comment on function auditoria.recusar_alteracao() is 'Bloqueio de UPDATE e DELETE em nivel de statement, inclusive contra service_role, como manda docs/04, secao 6. Fica registrado que superusuario e provedor ainda podem alterar: e o limite que a ancora diaria e o backup proprio cobrem.';

drop trigger if exists eventos_append_only on auditoria.eventos;
create trigger eventos_append_only
  before update or delete on auditoria.eventos
  for each statement execute function auditoria.recusar_alteracao();

alter table auditoria.eventos enable row level security;

create policy eventos_select_auditor on auditoria.eventos for select to authenticated
  using ((select public.autorizar('trilha.ler_completa'::public.permissao, null)));

create policy eventos_insert_proprio_ator on auditoria.eventos for insert to authenticated
  with check (
    ator_id = (select auth.uid())
    and (select private.is_workspace_member(workspace_id))
  );

revoke all on table auditoria.eventos from public, anon, authenticated, service_role;
grant select, insert on table auditoria.eventos to authenticated;
-- Cinto e suspensorio: sem grant de update e delete em lugar nenhum.
revoke update, delete on table auditoria.eventos from authenticated, anon, service_role;

-- ============================================================================
-- 4. auditoria.verificacoes e auditoria.ancoras
-- ============================================================================

create table if not exists auditoria.verificacoes (
  id                 bigint generated always as identity primary key,
  executado_em       timestamptz not null default now(),
  workspace_id       uuid references public.workspaces (id),
  fluxo              text not null references auditoria.fluxos (codigo),
  seq_final          bigint not null,
  ok                 boolean not null,
  primeira_quebra_seq bigint,
  duracao_ms         integer,
  origem             text not null check (origem in ('pg_cron','script'))
);

comment on table auditoria.verificacoes is 'Resultado de cada execucao do verificador da cadeia, por fluxo. E o que /verificar mostra como data e resultado da ultima verificacao. Origem script e a execucao de pnpm auditoria:verificar contra dump restaurado, que prova backup e cadeia juntos (docs/04, secao 6).';
comment on column auditoria.verificacoes.primeira_quebra_seq is 'Primeiro seq cujo hash nao confere; nulo quando a cadeia esta integra.';

create index if not exists verificacoes_fluxo_executado_em_idx on auditoria.verificacoes (fluxo, executado_em desc);

alter table auditoria.verificacoes enable row level security;

create policy verificacoes_select_auditor on auditoria.verificacoes for select to authenticated
  using ((select public.autorizar('trilha.ler_completa'::public.permissao, null)));

revoke all on table auditoria.verificacoes from public, anon, authenticated, service_role;
grant select on table auditoria.verificacoes to authenticated;
revoke update, delete on table auditoria.verificacoes from authenticated, anon, service_role;

create table if not exists auditoria.ancoras (
  dia            date not null,
  workspace_id   uuid not null references public.workspaces (id),
  hash_agregado  text not null check (hash_agregado ~ '^[0-9a-f]{64}$'),
  seq_finais     jsonb not null default '{}',
  prova_ots      bytea,
  ots_completa   boolean not null default false,
  bloco_bitcoin  integer,
  prova_tsr      bytea,
  publicado_em   timestamptz,
  atualizado_em  timestamptz not null default now(),
  primary key (workspace_id, dia)
);

comment on table auditoria.ancoras is 'Uma ancora por dia com o hash agregado das cabecas de todos os fluxos, prova OpenTimestamps e prova RFC 3161 opcional. Nivel 2 de docs/04, secao 6: opcional e reversivel, e a cadeia interna continua integra sem ela. Uma unica ancora por dia evita publicar ritmo e volume de aprovacoes por fluxo.';
comment on column auditoria.ancoras.seq_finais is 'Mapa fluxo para seq final do dia. So o auditor le: a lista publica mostra apenas dia e hash_agregado.';
comment on column auditoria.ancoras.prova_ots is 'Arquivo .ots, incompleto ate o upgrade nos calendarios; formato aberto, verificavel sem a intranet e sem fornecedor.';

alter table auditoria.ancoras enable row level security;

create policy ancoras_select_auditor on auditoria.ancoras for select to authenticated
  using ((select public.autorizar('trilha.ler_completa'::public.permissao, null)));

revoke all on table auditoria.ancoras from public, anon, authenticated, service_role;
grant select on table auditoria.ancoras to authenticated;
revoke update, delete on table auditoria.ancoras from authenticated, anon;

drop trigger if exists ancoras_toca_atualizado_em on auditoria.ancoras;
create trigger ancoras_toca_atualizado_em
  before update on auditoria.ancoras
  for each row execute function public.tocar_atualizado_em();

-- ============================================================================
-- 5. Registro de eventos e verificador
-- ============================================================================

-- Caminho de escrita da trilha para quem age pela borda. Existe porque o insert
-- de auditoria.registrar_evento precisa devolver seq, e num insert com returning
-- o Postgres tambem aplica a policy de select da tabela: eventos_select_auditor
-- so e verdadeira para quem tem trilha.ler_completa, entao a colaboradora comum
-- recebia 42501 ao gravar o proprio evento e o tramite inteiro das fases 4 e 5
-- travava, porque toda RPC passa por aqui.
create or replace function private.gravar_evento_da_sessao(
  p_workspace_id    uuid,
  p_fluxo           text,
  p_entidade_tipo   text,
  p_entidade_id     uuid,
  p_acao            text,
  p_papel           text,
  p_versao          integer,
  p_antes           jsonb,
  p_depois          jsonb,
  p_hash_arquivo    text,
  p_hash_decisao    text,
  p_ip_hash         text,
  p_user_agent_hash text
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
  v_ator uuid := (select auth.uid());
  v_seq  bigint;
begin
  -- A condicao de escrita nao afrouxa: e a mesma de eventos_insert_proprio_ator,
  -- reconferida aqui porque o definer passa por cima do RLS da tabela. O ator sai
  -- da sessao e nunca de parametro, entao continua sendo impossivel gravar evento
  -- em nome de terceiro. A regra de leitura da trilha fica intacta: quem nao tem
  -- trilha.ler_completa escreve e nao le.
  if v_ator is null then
    raise exception 'Evento de pessoa exige sessao autenticada; evento sem ator humano entra por auditoria.registrar_evento_do_sistema.'
      using errcode = '42501';
  end if;
  if not private.is_workspace_member(p_workspace_id) then
    raise exception 'Evento so entra na trilha do espaco de trabalho de que a pessoa participa.'
      using errcode = '42501';
  end if;

  insert into auditoria.eventos (
    workspace_id, fluxo, entidade_tipo, entidade_id, versao, ator_id, papel, acao,
    antes, depois, hash_arquivo, hash_decisao, ip_hash, user_agent_hash,
    hash_anterior, hash_linha
  ) values (
    p_workspace_id, p_fluxo, p_entidade_tipo, p_entidade_id, p_versao,
    v_ator, p_papel, p_acao,
    p_antes, p_depois, p_hash_arquivo, p_hash_decisao,
    p_ip_hash, p_user_agent_hash,
    repeat('0', 64), repeat('0', 64)
  )
  returning seq into v_seq;
  return v_seq;
end;
$$;

comment on function private.gravar_evento_da_sessao(uuid, text, text, uuid, text, text, integer, jsonb, jsonb, text, text, text, text) is 'Caminho de escrita da trilha para o ator da sessao, no padrao das demais auxiliares de private: security definer com search_path vazio. Nasceu de defeito encontrado pela suite pgTAP do anexo 02b, teste 92 (uma colaboradora comum consegue gravar o proprio evento na trilha): auditoria.registrar_evento devolve seq por returning, e insert com returning tambem passa pela policy de select, que so e verdadeira para quem tem trilha.ler_completa; o resultado era 42501 para quem nao e auditor, administrador ou encarregado, e como toda RPC das fases 4 e 5 chama o ajudante, abrir, submeter, decidir, retirar, assinar e publicar travavam. So o caminho da escrita mudou: a regra de leitura de auditoria.eventos continua sendo eventos_select_auditor, e as duas condicoes de eventos_insert_proprio_ator (ator igual ao da sessao e pertencimento ao espaco) sao reconferidas aqui, com o ator lido de auth.uid() e nunca de parametro.';

create or replace function auditoria.registrar_evento(
  p_workspace_id  uuid,
  p_fluxo         text,
  p_entidade_tipo text,
  p_entidade_id   uuid,
  p_acao          text,
  p_papel         text default 'membro',
  p_versao        integer default null,
  p_antes         jsonb default null,
  p_depois        jsonb default null,
  p_hash_arquivo  text default null,
  p_hash_decisao  text default null,
  p_ip            inet default null,
  p_user_agent    text default null
) returns bigint
language plpgsql security invoker set search_path = '' as $$
begin
  return private.gravar_evento_da_sessao(
    p_workspace_id, p_fluxo, p_entidade_tipo, p_entidade_id, p_acao, p_papel, p_versao,
    p_antes, p_depois, p_hash_arquivo, p_hash_decisao,
    public.hash_curto(host(p_ip)), public.hash_curto(p_user_agent)
  );
end;
$$;

comment on function auditoria.registrar_evento(uuid, text, text, uuid, text, text, integer, jsonb, jsonb, text, text, inet, text) is 'Helper das RPCs e de lib/auditoria/registrar.ts, que continua sendo a porta unica de escrita da trilha por pessoa: hasheia IP e agente e delega a gravacao a private.gravar_evento_da_sessao. O insert deixou de acontecer aqui por defeito que a suite pgTAP do anexo 02b apontou no teste 92: com returning seq o Postgres aplica tambem a policy de select da trilha, e quem nao tem trilha.ler_completa levava 42501 ao gravar o proprio evento, travando todo o tramite das fases 4 e 5. hash_anterior e hash_linha entram como marcador e sao substituidos pelo trigger de encadeamento, e ninguem grava evento em nome de terceiro, porque o ator sai de auth.uid() dentro da auxiliar.';

create or replace function auditoria.registrar_evento_do_sistema(
  p_workspace_id  uuid,
  p_fluxo         text,
  p_entidade_tipo text,
  p_entidade_id   uuid,
  p_acao          text,
  p_versao        integer default null,
  p_antes         jsonb default null,
  p_depois        jsonb default null,
  p_hash_arquivo  text default null,
  p_hash_decisao  text default null
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare v_seq bigint;
begin
  insert into auditoria.eventos (
    workspace_id, fluxo, entidade_tipo, entidade_id, versao, ator_id, papel, acao,
    antes, depois, hash_arquivo, hash_decisao, hash_anterior, hash_linha
  ) values (
    p_workspace_id, p_fluxo, p_entidade_tipo, p_entidade_id, p_versao,
    null, 'sistema', p_acao, p_antes, p_depois, p_hash_arquivo, p_hash_decisao,
    repeat('0', 64), repeat('0', 64)
  )
  returning seq into v_seq;
  return v_seq;
end;
$$;

comment on function auditoria.registrar_evento_do_sistema(uuid, text, text, uuid, text, integer, jsonb, jsonb, text, text) is 'Eventos sem ator humano (decurso de prazo, escalonamento, verificador, ancora): ator_id nulo e papel sistema, como o protocolo AUTO do Jorvik. So o job e a chave de servico executam.';

create or replace function auditoria.verificar_cadeia(
  p_fluxo  text default null,
  p_origem text default 'pg_cron'
) returns table (fluxo text, seq_final bigint, ok boolean, primeira_quebra_seq bigint)
language plpgsql security definer set search_path = '' as $$
declare
  r_fluxo    record;
  r_evento   record;
  v_esperado text;
  v_calc     text;
  v_ok       boolean;
  v_quebra   bigint;
  v_final    bigint;
  v_inicio   timestamptz;
  v_ws       uuid;
begin
  for r_fluxo in select f.codigo from auditoria.fluxos f
                  where p_fluxo is null or f.codigo = p_fluxo
                  order by f.codigo loop
    v_inicio   := clock_timestamp();
    v_esperado := repeat('0', 64);
    v_ok       := true;
    v_quebra   := null;
    v_final    := 0;
    v_ws       := null;

    for r_evento in select * from auditoria.eventos e
                     where e.fluxo = r_fluxo.codigo
                     order by e.ordem_no_fluxo loop
      v_calc := encode(sha256(convert_to(concat_ws('|',
          r_evento.seq::text,
          r_evento.ordem_no_fluxo::text,
          to_char(r_evento.ocorrido_em at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF'),
          r_evento.workspace_id::text,
          r_evento.fluxo,
          r_evento.entidade_tipo,
          r_evento.entidade_id::text,
          coalesce(r_evento.versao::text, ''),
          coalesce(r_evento.ator_id::text, ''),
          r_evento.papel,
          r_evento.acao,
          coalesce(r_evento.antes::text, ''),
          coalesce(r_evento.depois::text, ''),
          coalesce(r_evento.hash_arquivo, ''),
          coalesce(r_evento.hash_decisao, ''),
          coalesce(r_evento.ip_hash, ''),
          coalesce(r_evento.user_agent_hash, ''),
          r_evento.hash_anterior
        ), 'UTF8')), 'hex');

      if v_ok and (r_evento.hash_anterior <> v_esperado or r_evento.hash_linha <> v_calc) then
        v_ok     := false;
        v_quebra := r_evento.seq;
      end if;

      v_esperado := r_evento.hash_linha;
      v_final    := r_evento.seq;
      v_ws       := r_evento.workspace_id;
    end loop;

    insert into auditoria.verificacoes (workspace_id, fluxo, seq_final, ok, primeira_quebra_seq, duracao_ms, origem)
    values (v_ws, r_fluxo.codigo, v_final, v_ok, v_quebra,
            (extract(epoch from (clock_timestamp() - v_inicio)) * 1000)::integer,
            p_origem);

    if v_ws is not null then
      perform auditoria.registrar_evento_do_sistema(
        v_ws, r_fluxo.codigo, 'auditoria.eventos', gen_random_uuid(),
        case when v_ok then 'auditoria.verificacao_ok' else 'auditoria.verificacao_falhou' end,
        null, null, jsonb_build_object('estado', case when v_ok then 'ok' else 'quebrada' end)
      );
    end if;

    fluxo := r_fluxo.codigo;
    seq_final := v_final;
    ok := v_ok;
    primeira_quebra_seq := v_quebra;
    return next;
  end loop;
end;
$$;

comment on function auditoria.verificar_cadeia(text, text) is 'Verificador que percorre auditoria.eventos por fluxo e ordem_no_fluxo, recalcula hash_linha, confere hash_anterior e grava o resultado em auditoria.verificacoes (docs/04, secao 6). Roda por pg_cron uma vez ao dia e por pnpm auditoria:verificar contra dump restaurado no teste trimestral de restauracao. O execute e concedido a service_role, no mesmo degrau de public.processar_prazos_autorizacao, e continua revogado de public, anon e authenticated: sem ele o script de verificacao so rodava conectado como dono do banco, o que contraria a secao 10.5 do escopo e deixava o valor script de auditoria.verificacoes.origem sem quem o escrevesse. Falta apontada pela suite pgTAP do anexo 02b, secao 4, que exercita a funcao justamente com origem script.';

revoke all on function auditoria.registrar_evento(uuid, text, text, uuid, text, text, integer, jsonb, jsonb, text, text, inet, text) from public, anon;
revoke all on function private.gravar_evento_da_sessao(uuid, text, text, uuid, text, text, integer, jsonb, jsonb, text, text, text, text) from public, anon;
revoke all on function auditoria.registrar_evento_do_sistema(uuid, text, text, uuid, text, integer, jsonb, jsonb, text, text) from public, anon, authenticated;
revoke all on function auditoria.verificar_cadeia(text, text) from public, anon, authenticated;
grant execute on function auditoria.registrar_evento(uuid, text, text, uuid, text, text, integer, jsonb, jsonb, text, text, inet, text) to authenticated;
grant execute on function private.gravar_evento_da_sessao(uuid, text, text, uuid, text, text, integer, jsonb, jsonb, text, text, text, text) to authenticated;
-- Evento sem ator humano so sai do job: D39 manda os lembretes por rota da
-- intranet chamada pelo cron da Vercel, e o caminho de contingencia sem pg_cron
-- usa a chave de servico. Nem authenticated nem anon executam.
grant execute on function auditoria.registrar_evento_do_sistema(uuid, text, text, uuid, text, integer, jsonb, jsonb, text, text) to service_role;
-- O verificador tambem sai pela chave de servico, no mesmo degrau de
-- public.processar_prazos_autorizacao: auditoria.verificacoes.origem admite
-- 'script' e a secao 10.5 do escopo promete o pnpm auditoria:verificar rodando a
-- mesma funcao contra dump restaurado, o que so o dono do banco conseguia fazer.
-- Apontado pela suite pgTAP do anexo 02b, secao 4, que exercita
-- auditoria.verificar_cadeia com origem 'script'. Nem authenticated nem anon
-- executam: o verificador escreve em auditoria.verificacoes e grava evento de
-- sistema na cadeia.
grant execute on function auditoria.verificar_cadeia(text, text) to service_role;

-- ============================================================================
-- 6. public.autorizacao_regras
-- ============================================================================

create table if not exists public.autorizacao_regras (
  id                      uuid primary key default gen_random_uuid(),
  workspace_id            uuid not null references public.workspaces (id) on delete cascade,
  tipo_ato                public.tipo_ato not null,
  titulo                  text not null check (btrim(titulo) <> ''),
  descricao               text,
  tipo                    text not null check (tipo in ('light','document')),
  solicitantes            jsonb not null default '[]',
  etapas                  jsonb not null default '[]',
  tipo_gestao_padrao      text not null default 'manual' check (tipo_gestao_padrao in ('manual','auto_approve','auto_deny')),
  prazo_dias_uteis_padrao smallint not null default 5 check (prazo_dias_uteis_padrao between 1 and 60),
  politica_assinatura_id  uuid references public.politicas_assinatura (id),
  desaprovar_se_alterado  boolean not null default true,
  publica_no_mural        boolean not null default false,
  arquivar_apos_dias      integer check (arquivar_apos_dias is null or arquivar_apos_dias between 1 and 3650),
  fluxo_codigo            text not null references auditoria.fluxos (codigo),
  ativo                   boolean not null default true,
  criado_por              uuid references public.profiles (id) on delete set null,
  criado_em               timestamptz not null default now(),
  atualizado_em           timestamptz not null default now(),
  constraint autorizacao_regras_tipo_ato_unico unique (workspace_id, tipo_ato),
  constraint autorizacao_regras_documento_sem_auto check (
    tipo = 'light' or tipo_gestao_padrao = 'manual'
  )
);

comment on table public.autorizacao_regras is 'Modelo de tramite por tipo de ato: quem pode pedir, etapas encadeadas com papel aprovador por setor, quorum, prazos, acao ao expirar e invalidacao por alteracao de arquivo. Transposta de approval_rules, approval_rule_requesters e approval_rule_approvers do Nextcloud Approval, com a configuracao por tipo de fluxo do XWiki Publication Workflow. Nao guarda nivel de assinatura nem base legal: aponta para politicas_assinatura e o registro do art. 37 vive em lgpd.operacoes.';
comment on column public.autorizacao_regras.solicitantes is 'Lista de {papel, setor_id ou null}, no molde de approval_rule_requesters do Nextcloud Approval.';
comment on column public.autorizacao_regras.etapas is 'Lista ordenada de {ordem, papel_aprovador, setor_id ou "origem", quorum, prazo_dias_uteis, acao_ao_expirar}. Copiada para autorizacao_etapas na submissao, para que regra alterada depois nao mude pedido em curso.';
comment on column public.autorizacao_regras.desaprovar_se_alterado is 'unapprove_when_modified do Nextcloud Approval: versao nova depois da aprovacao devolve o documento a draft com o evento documento.aprovacao_invalidada.';
comment on column public.autorizacao_regras.fluxo_codigo is 'Codigo neutro gravado na trilha; o nome do fluxo fica so em auditoria.fluxos.';
comment on constraint autorizacao_regras_documento_sem_auto on public.autorizacao_regras is 'Documento nunca e aprovado por decurso de prazo; auto_approve e auto_deny valem so para tramite leve cuja regra os autorize.';

create index if not exists autorizacao_regras_workspace_id_ativo_idx on public.autorizacao_regras (workspace_id, ativo);

alter table public.autorizacao_regras enable row level security;

create policy autorizacao_regras_select_membro on public.autorizacao_regras for select to authenticated
  using ((select private.is_workspace_member(workspace_id)));

create policy autorizacao_regras_insert_regrador on public.autorizacao_regras for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and (select public.autorizar('autorizacao.regrar'::public.permissao, null))
    and (select private.exige_aal2())
    and criado_por = (select auth.uid())
  );

create policy autorizacao_regras_update_regrador on public.autorizacao_regras for update to authenticated
  using (
    (select private.is_workspace_member(workspace_id))
    and (select public.autorizar('autorizacao.regrar'::public.permissao, null))
  )
  with check (
    (select private.is_workspace_member(workspace_id))
    and (select public.autorizar('autorizacao.regrar'::public.permissao, null))
    and (select private.exige_aal2())
  );

revoke all on table public.autorizacao_regras from public, anon;
grant select, insert, update on table public.autorizacao_regras to authenticated;

drop trigger if exists autorizacao_regras_toca_atualizado_em on public.autorizacao_regras;
create trigger autorizacao_regras_toca_atualizado_em
  before update on public.autorizacao_regras
  for each row execute function public.tocar_atualizado_em();

-- Seed das regras de tramite: uma linha ativa por valor de public.tipo_ato que
-- tramita, do leve ao documento. Sem ele, public.abrir_autorizacao levanta
-- 'Nao ha regra ativa para este tipo de ato' em todo pedido e a fase 4 nao sai
-- do zero. Idempotente, no padrao dos demais seeds. fluxo_codigo e F01 no
-- tramite por documento e F02 no leve; setor_id 'origem' nas etapas e o setor do
-- proprio pedido, resolvido em public.abrir_autorizacao; politica_assinatura_id
-- aponta para a linha vigente de public.politicas_assinatura semeada na parte
-- base, unica fonte normativa do nivel da Lei 14.063/2020 (D04). Prazos de D35:
-- leve 5 dias uteis, coordenacao 5, homologacao 10. Nenhum dado pessoal em seed.
insert into public.autorizacao_regras (
  workspace_id, tipo_ato, titulo, descricao, tipo, solicitantes, etapas,
  prazo_dias_uteis_padrao, politica_assinatura_id, fluxo_codigo
)
select w.id, r.tipo_ato::public.tipo_ato, r.titulo, r.descricao, r.tipo,
       r.solicitantes::jsonb, r.etapas::jsonb, r.prazo_dias_uteis_padrao,
       pol.id, r.fluxo_codigo
from public.workspaces w
cross join (values
  ('uso_imagem', 'Uso de imagem em peca de comunicacao',
   'Uso de foto ou video de pessoa identificavel em peca da instituicao; quem decide e a Comunicacao.',
   'light',
   '[{"papel":"voluntario","setor_id":null},{"papel":"colaborador","setor_id":null},{"papel":"instrutor","setor_id":null},{"papel":"coordenador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"comunicacao","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"}]',
   5, 'F02'),

  ('participacao_acao', 'Participacao em acao',
   'Participacao de voluntario em acao do setor, decidida pelo coordenador do setor de origem.',
   'light',
   '[{"papel":"voluntario","setor_id":null},{"papel":"colaborador","setor_id":null},{"papel":"instrutor","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"}]',
   5, 'F02'),

  ('autorizacao_despesa', 'Autorizacao previa de despesa',
   'Ato previo ao gasto, com objeto, valor estimado, atividade e vigencia em autorizacoes.dados; a Lei 9.608 so admite ressarcir despesa expressamente autorizada antes do gasto.',
   'light',
   '[{"papel":"voluntario","setor_id":null},{"papel":"colaborador","setor_id":null},{"papel":"coordenador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"}]',
   5, 'F02'),

  ('ressarcimento', 'Ressarcimento de despesa autorizada',
   'Ato posterior ao gasto: so abre com uma autorizacao_despesa aprovada e vigente informada em autorizacoes.dados, conferida por public.abrir_autorizacao (Lei 9.608).',
   'light',
   '[{"papel":"voluntario","setor_id":null},{"papel":"colaborador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F02'),

  ('acesso_pasta', 'Acesso a pasta restrita',
   'Pedido de leitura de pasta restrita do setor, decidido pelo coordenador do setor de origem.',
   'light',
   '[{"papel":"voluntario","setor_id":null},{"papel":"colaborador","setor_id":null},{"papel":"instrutor","setor_id":null},{"papel":"coordenador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"}]',
   5, 'F02'),

  ('reativacao_vinculo', 'Reativacao de vinculo',
   'Pedido de quem esta com vinculo inactive para voltar a atuar; quem decide e a Secretaria.',
   'light',
   '[{"papel":"voluntario","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"secretaria","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"}]',
   5, 'F02'),

  ('termo_adesao', 'Termo de adesao do voluntario',
   'Termo da Lei 9.608, art. 2, conferido pela Secretaria e homologado pela Diretoria.',
   'document',
   '[{"papel":"secretaria","setor_id":null},{"papel":"coordenador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"secretaria","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('termo_desligamento', 'Termo de desligamento',
   'Encerramento do vinculo, conferido pela Secretaria e homologado pela Diretoria.',
   'document',
   '[{"papel":"secretaria","setor_id":null},{"papel":"coordenador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"secretaria","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('consentimento_lgpd', 'Consentimento LGPD',
   'Termo de consentimento do art. 8 da LGPD, conferido pela Secretaria e homologado pela Diretoria.',
   'document',
   '[{"papel":"secretaria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"secretaria","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('autorizacao_imagem', 'Autorizacao de uso de imagem',
   'Autorizacao assinada pelo titular (art. 7, I, da LGPD e art. 20 do Codigo Civil), conferida pela Comunicacao e homologada pela Diretoria.',
   'document',
   '[{"papel":"secretaria","setor_id":null},{"papel":"comunicacao","setor_id":null},{"papel":"coordenador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"comunicacao","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('ata_junta', 'Ata de reuniao da Junta',
   'Ata redigida e enviada aos membros em ate 15 dias (Estatuto art. 33, paragrafo 1, estendido as Juntas Estaduais pelo paragrafo 3); guarda permanente.',
   'document',
   '[{"papel":"secretaria","setor_id":null},{"papel":"diretoria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   10, 'F01'),

  ('ata_assembleia', 'Ata de assembleia',
   'Ata de assembleia, homologada pela Diretoria; guarda permanente.',
   'document',
   '[{"papel":"secretaria","setor_id":null},{"papel":"diretoria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   10, 'F01'),

  ('ata_diretoria', 'Ata de reuniao da Diretoria',
   'Ata de reuniao da Diretoria, homologada pela propria Diretoria; guarda permanente.',
   'document',
   '[{"papel":"secretaria","setor_id":null},{"papel":"diretoria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   10, 'F01'),

  ('oficio', 'Oficio',
   'Expediente com numero de registro sequencial por ano; coordenacao confere e a Diretoria homologa antes da expedicao.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"secretaria","setor_id":null},{"papel":"comunicacao","setor_id":null},{"papel":"diretoria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('parecer', 'Parecer',
   'Parecer tecnico do setor, conferido pela coordenacao e homologado pela Diretoria.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"colaborador","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('prestacao_contas', 'Prestacao de contas',
   'Prestacao de contas de parceria (MROSC art. 68), conferida pela coordenacao e homologada pela Diretoria; guarda de 10 anos.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"secretaria","setor_id":null},{"papel":"diretoria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('politica', 'Politica institucional',
   'Politica com vigencia e data de revisao, conferida pela coordenacao e homologada pela Diretoria.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"secretaria","setor_id":null},{"papel":"diretoria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('procedimento', 'Procedimento',
   'Procedimento operacional do setor, conferido pela coordenacao e homologado pela Diretoria.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"instrutor","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('relatorio', 'Relatorio',
   'Relatorio de atividade do setor, conferido pela coordenacao e homologado pela Diretoria.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"colaborador","setor_id":null},{"papel":"instrutor","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01'),

  ('certificado', 'Certificado',
   'Certificado emitido pela instituicao, conferido pela coordenacao e homologado pela Diretoria. O certificado do Curso de Puncao Venosa continua no projeto proprio e nao tramita aqui.',
   'document',
   '[{"papel":"coordenador","setor_id":null},{"papel":"instrutor","setor_id":null},{"papel":"secretaria","setor_id":null}]',
   '[{"ordem":1,"papel_aprovador":"coordenador","setor_id":"origem","quorum":1,"prazo_dias_uteis":5,"acao_ao_expirar":"escalate"},{"ordem":2,"papel_aprovador":"diretoria","setor_id":"origem","quorum":1,"prazo_dias_uteis":10,"acao_ao_expirar":"escalate"}]',
   5, 'F01')
) as r(tipo_ato, titulo, descricao, tipo, solicitantes, etapas, prazo_dias_uteis_padrao, fluxo_codigo)
left join lateral (
  select pa.id
    from public.politicas_assinatura pa
   where pa.workspace_id = w.id
     and pa.tipo_ato = r.tipo_ato::public.tipo_ato
     and pa.vigencia_inicio <= current_date
   order by pa.vigencia_inicio desc
   limit 1
) pol on true
where w.kind = 'production'
on conflict do nothing;

-- ============================================================================
-- 7. public.autorizacoes
-- ============================================================================

create table if not exists public.autorizacoes (
  id                        uuid primary key default gen_random_uuid(),
  workspace_id              uuid not null references public.workspaces (id) on delete cascade,
  tipo                      text not null check (tipo in ('light','document')),
  tipo_ato                  public.tipo_ato not null,
  regra_id                  uuid not null references public.autorizacao_regras (id),
  objeto_tipo               text not null check (objeto_tipo in (
                              'documentos','documento_versoes','files','pastas','profiles','vinculos','avisos','grupos'
                            )),
  objeto_id                 uuid not null,
  versao_id                 uuid references public.documento_versoes (id),
  hash_arquivo_submissao    text check (hash_arquivo_submissao ~ '^[0-9a-f]{64}$'),
  rodada                    smallint not null default 1 check (rodada >= 1),
  sequencia_do_objeto       smallint not null default 1,
  solicitante_id            uuid not null references public.profiles (id),
  setor_id                  uuid not null references public.setores (id),
  estado                    text not null,
  etapa_atual               smallint,
  dados                     jsonb not null default '{}',
  prazo_em                  timestamptz,
  motivo_negacao            text,
  tipo_gestao               text not null default 'manual' check (tipo_gestao in ('manual','auto_approve','auto_deny')),
  automatica                boolean not null default false,
  nivel_assinatura_exigido  public.nivel_assinatura not null default 'nenhuma',
  codigo_verificacao        text not null unique default public.gerar_codigo_verificacao()
                              check (codigo_verificacao ~ '^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$'),
  consultas_publicas        integer not null default 0 check (consultas_publicas >= 0),
  retirada_em               timestamptz,
  concluida_em              timestamptz,
  publicada_em              timestamptz,
  arquivar_em               timestamptz,
  criado_em                 timestamptz not null default now(),
  atualizado_em             timestamptz not null default now(),
  constraint autorizacoes_objeto_rodada_unica unique (workspace_id, objeto_tipo, objeto_id, sequencia_do_objeto),
  constraint autorizacoes_estado_por_tipo check (
    (tipo = 'light'
      and estado in ('pending','approved','denied','withdrawn','auto_approved','expired'))
    or (tipo = 'document'
      and estado in ('draft','in_review','in_validation','changes_requested','rejected',
                     'withdrawn','approved','signing','published','archived'))
  ),
  constraint autorizacoes_motivo_negacao_obrigatorio check (
    estado not in ('denied','rejected') or coalesce(btrim(motivo_negacao), '') <> ''
  ),
  constraint autorizacoes_documento_com_versao check (
    tipo = 'light'
    or estado = 'draft'
    or (versao_id is not null and hash_arquivo_submissao is not null)
  )
);

comment on table public.autorizacoes is 'Cabecalho generico de todo pedido, leve ou por documento, ligado a qualquer objeto por tipo e id. Transposta da classe Autorizzazione do Jorvik (richiedente, concessa, motivo_negazione, oggetto_tipo/oggetto_id, progressivo, scadenza, tipo_gestione, automatica) com a maquina de estados do XWiki Publication Workflow e a regra do SEI de que minuta nao tramita.';
comment on column public.autorizacoes.rodada is 'Progressivo do Jorvik dentro de um mesmo pedido: conta as submissoes, e a resubmissao apos devolucao incrementa a rodada na propria linha, sem tocar a unicidade.';
comment on column public.autorizacoes.sequencia_do_objeto is 'Conta os pedidos abertos sobre o mesmo objeto: e este contador, e nao rodada, que entra em autorizacoes_objeto_rodada_unica. Pedido novo sobre o mesmo objeto nasce com o sucessor do maior valor existente e nunca reabre o anterior.';
comment on column public.autorizacoes.hash_arquivo_submissao is 'SHA-256 congelado na submissao. Base da regra do etag do Nextcloud Approval: decidir sobre arquivo alterado e recusado.';
comment on column public.autorizacoes.tipo_gestao is 'tipo_gestione do Jorvik; auto_approve e auto_deny so em tramite leve autorizado pela regra.';
comment on column public.autorizacoes.codigo_verificacao is 'Credencial de 128 bits da pagina publica /verificar/[codigo]. Molde do /validar/[token] do Curso.';
comment on column public.autorizacoes.consultas_publicas is 'Contador de consultas em /verificar, sem IP: a minimizacao do art. 6, III, da LGPD vale tambem para o contador.';
comment on column public.autorizacoes.nivel_assinatura_exigido is 'Copia congelada na submissao do nivel de politicas_assinatura (Lei 14.063/2020, art. 4). Nenhuma outra tabela repete a regra.';

create index if not exists autorizacoes_workspace_id_estado_prazo_em_idx on public.autorizacoes (workspace_id, estado, prazo_em);
create index if not exists autorizacoes_solicitante_id_idx               on public.autorizacoes (solicitante_id, criado_em desc);
create index if not exists autorizacoes_objeto_tipo_objeto_id_idx        on public.autorizacoes (objeto_tipo, objeto_id);
create index if not exists autorizacoes_setor_id_estado_idx              on public.autorizacoes (setor_id, estado);

-- ============================================================================
-- 8. public.autorizacao_etapas
-- ============================================================================

create table if not exists public.autorizacao_etapas (
  id                  uuid primary key default gen_random_uuid(),
  workspace_id        uuid not null references public.workspaces (id) on delete cascade,
  autorizacao_id      uuid not null references public.autorizacoes (id) on delete cascade,
  ordem               smallint not null check (ordem >= 1),
  papel_aprovador     text not null references public.papeis (slug),
  setor_id            uuid not null references public.setores (id),
  quorum              smallint not null default 1 check (quorum >= 1),
  prazo_dias_uteis    smallint not null check (prazo_dias_uteis between 1 and 60),
  acao_ao_expirar     text not null default 'escalate'
                        check (acao_ao_expirar in ('remind','escalate','auto_approve','auto_deny')),
  estado              text not null default 'waiting'
                        check (estado in ('waiting','open','approved','returned','rejected','escalated','skipped','expired')),
  aberta_em           timestamptz,
  prazo_em            timestamptz,
  lembrete_enviado_em timestamptz,
  escalada_em         timestamptz,
  fechada_em          timestamptz,
  fechada_por         uuid references public.profiles (id) on delete set null,
  criado_em           timestamptz not null default now(),
  constraint autorizacao_etapas_ordem_unica unique (autorizacao_id, ordem)
);

comment on table public.autorizacao_etapas is 'Etapas instanciadas de um pedido, copiadas da regra na submissao para que regra alterada depois nao mude pedido em curso (snapshot de eligible_voters do DRK Rundlaufbeschluesse). Encadeamento no molde do Nextcloud Approval, em que a etapa aprovada abre a seguinte; prazo, acao ao expirar e escalonamento no molde de WorkflowStateEscalation do Mayan. E o que a aba Precisa de voce consulta.';
comment on column public.autorizacao_etapas.acao_ao_expirar is 'remind, escalate, auto_approve ou auto_deny. Documento nunca aceita auto_approve; a regra ja recusa na criacao.';
comment on column public.autorizacao_etapas.aberta_em is 'Marca a rodada corrente: uma decisao so conta se decidido_em for posterior a esta data, o que permite reabrir a mesma etapa em nova rodada sem duplicar linha.';

create index if not exists autorizacao_etapas_autorizacao_id_ordem_idx on public.autorizacao_etapas (autorizacao_id, ordem);
create index if not exists autorizacao_etapas_estado_prazo_em_idx      on public.autorizacao_etapas (estado, prazo_em) where estado = 'open';
create index if not exists autorizacao_etapas_papel_aprovador_setor_id_idx on public.autorizacao_etapas (papel_aprovador, setor_id, estado);

-- ============================================================================
-- 9. public.autorizacao_decisoes
-- ============================================================================

create table if not exists public.autorizacao_decisoes (
  id             uuid primary key default gen_random_uuid(),
  workspace_id   uuid not null references public.workspaces (id) on delete cascade,
  autorizacao_id uuid not null references public.autorizacoes (id) on delete cascade,
  etapa_id       uuid not null references public.autorizacao_etapas (id) on delete cascade,
  ator_id        uuid references public.profiles (id) on delete set null,
  papel_exercido text not null,
  delegacao_id   uuid references public.delegacoes (id),
  decisao        text not null check (decisao in
                    ('approved','returned','rejected','withdrawn','auto_approved','auto_denied','escalated')),
  motivo         text,
  hash_versao    text check (hash_versao  ~ '^[0-9a-f]{64}$'),
  hash_decisao   text not null check (hash_decisao ~ '^[0-9a-f]{64}$'),
  aal            text check (aal in ('aal1','aal2')),
  ip             inet,
  user_agent     text,
  decidido_em    timestamptz not null default now(),
  constraint autorizacao_decisoes_motivo_obrigatorio check (
    decisao not in ('returned','rejected') or coalesce(btrim(motivo), '') <> ''
  ),
  constraint autorizacao_decisoes_sistema_sem_ator check (
    (ator_id is not null and papel_exercido <> 'sistema')
    or (ator_id is null and papel_exercido = 'sistema')
  )
);
comment on table public.autorizacao_decisoes is 'Uma linha por decisao de uma pessoa ou do sistema em uma etapa. Transposta de approval_activity do Nextcloud Approval (file_id, rule_id, user_id, new_state, message, timestamp), de Autorizzazione.firma do Jorvik (firmatario, concessa, motivo_negazione, automatica) e de approval_voters da Redacao (decision, comment, decided_at). E a tabela apagavel que guarda o que a cadeia nao pode guardar: o motivo e o endereco.';
comment on column public.autorizacao_decisoes.motivo is 'Parecer ou motivo da negacao. Dado apagavel: nunca vai a auditoria.eventos, que recebe apenas hash_decisao.';
comment on column public.autorizacao_decisoes.hash_versao is 'SHA-256 conferido no ato da decisao (regra do etag do Nextcloud Approval).';
comment on column public.autorizacao_decisoes.hash_decisao is 'SHA-256 do JSON canonico da decisao, o mesmo gravado na cadeia.';
comment on column public.autorizacao_decisoes.ip is 'Endereco em claro, apagado pela anonimizacao do titular. Na trilha entra apenas ip_hash.';
comment on column public.autorizacao_decisoes.delegacao_id is 'Delegacao por ausencia usada, no molde da Delega do Jorvik e da redistribuicao de tarefas por ausencia do e-ARQ Brasil 2. O delegado continua sujeito a regra de conflito de interesse.';

create index if not exists autorizacao_decisoes_autorizacao_id_idx    on public.autorizacao_decisoes (autorizacao_id, decidido_em desc);
create index if not exists autorizacao_decisoes_etapa_id_ator_id_idx  on public.autorizacao_decisoes (etapa_id, ator_id);

-- ============================================================================
-- 10. public.assinaturas
-- ============================================================================

create table if not exists public.assinaturas (
  id                       uuid primary key default gen_random_uuid(),
  workspace_id             uuid not null references public.workspaces (id) on delete cascade,
  autorizacao_id           uuid not null references public.autorizacoes (id) on delete cascade,
  documento_id             uuid references public.documentos (id),
  versao_id                uuid references public.documento_versoes (id),
  signatario_id            uuid not null references public.profiles (id),
  nivel                    public.nivel_assinatura not null check (nivel <> 'nenhuma'),
  metodo                   text not null check (metodo in ('totp','govbr','icp_brasil','externo')),
  estado                   text not null default 'pending'
                             check (estado in ('pending','generated','uploaded','verified','rejected','completed')),
  hash_arquivo             text not null check (hash_arquivo      ~ '^[0-9a-f]{64}$'),
  hash_pdf_gerado          text check (hash_pdf_gerado            ~ '^[0-9a-f]{64}$'),
  pdf_gerado_path          text,
  hash_pdf_assinado        text check (hash_pdf_assinado          ~ '^[0-9a-f]{64}$'),
  pdf_assinado_path        text,
  hash_confere             boolean,
  resultado_validador      text check (resultado_validador in
                             ('aprovado','invalido','indeterminado','assinatura_desconhecida')),
  relatorio_validador_path text,
  conferido_por            uuid references public.profiles (id) on delete set null,
  conferido_em             timestamptz,
  certificado_emissor      text,
  aal                      text check (aal in ('aal1','aal2')),
  ip                       inet,
  user_agent               text,
  codigo_verificacao       text not null unique default public.gerar_codigo_verificacao()
                             check (codigo_verificacao ~ '^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$'),
  assinado_em              timestamptz,
  criado_em                timestamptz not null default now(),
  constraint assinaturas_conferente_distinto check (conferido_por is null or conferido_por <> signatario_id),
  constraint assinaturas_aceite_exige_aal2 check (metodo <> 'totp' or aal = 'aal2'),
  constraint assinaturas_completa_com_evidencia check (
    estado <> 'completed'
    or (metodo = 'totp' and assinado_em is not null)
    or (hash_confere is true and resultado_validador = 'aprovado')
  )
);

comment on table public.assinaturas is 'Evidencia de cada assinatura por documento e nivel (Lei 14.063/2020, art. 4): hash do conteudo, PDF gerado e PDF assinado com a conferencia de prefixo que a atualizacao incremental do assinador gov.br permite, resultado registrado do validador do ITI, emissor do certificado, MFA, IP e data. Recorte de evidencias transposto do DocumentAuditLog do Documenso e do attachments com sha256 do DRK Rundlaufbeschluesse; codigo de verificacao no molde do /validar/[token] do Curso.';
comment on column public.assinaturas.hash_confere is 'Prefixo do PDF assinado igual ao PDF gerado e presenca de /ByteRange e /Contents. O gov.br assina por atualizacao incremental, entao o arquivo assinado comeca com os bytes exatos do original.';
comment on column public.assinaturas.resultado_validador is 'As quatro palavras que validar.iti.gov.br devolve, gravadas em portugues porque traduzir perderia a referencia.';
comment on constraint assinaturas_conferente_distinto on public.assinaturas is 'Ninguem atesta a propria assinatura: quem registra o resultado do validador e distinto do signatario.';
comment on constraint assinaturas_completa_com_evidencia on public.assinaturas is 'So fecha como completed o aceite interno com data, ou a assinatura cujo hash confere e cujo validador do ITI devolveu aprovado.';

create index if not exists assinaturas_autorizacao_id_idx on public.assinaturas (autorizacao_id);
create index if not exists assinaturas_documento_id_idx   on public.assinaturas (documento_id);
create index if not exists assinaturas_signatario_id_estado_idx on public.assinaturas (signatario_id, estado);

-- ============================================================================
-- 11. Funcoes auxiliares de RLS em private
-- ============================================================================

-- private.tem_papel(p_papel text, p_setor_id uuid default null) e definida na
-- parte base, com o join em public.papeis, a exigencia de p.ativo e o valor
-- padrao nulo no segundo parametro de que a policy usuario_papeis_insert_concessor
-- depende. Esta parte apenas a usa: redefini-la aqui derrubaria a migracao.

create or replace function private.delegacao_para(p_papel text, p_setor_id uuid)
returns uuid language sql security definer set search_path = '' stable as $$
  select d.id from public.delegacoes d
  where d.delegado_id = (select auth.uid())
    and d.papel = p_papel
    and (d.setor_id is null or d.setor_id = p_setor_id)
    and d.inicio <= now()
    and (d.fim is null or d.fim > now())
  order by d.inicio desc
  limit 1;
$$;

comment on function private.delegacao_para(text, uuid) is 'Delegacao por ausencia vigente para o papel e o setor pedidos, no molde da Delega do Jorvik (inizio, fine). Vale so para o mesmo papel no mesmo setor ou para papel global.';

create or replace function private.pode_decidir_etapa(p_etapa_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1 from public.autorizacao_etapas e
    where e.id = p_etapa_id
      and e.estado = 'open'
      and (
        private.tem_papel(e.papel_aprovador, e.setor_id)
        or private.delegacao_para(e.papel_aprovador, e.setor_id) is not null
      )
  );
$$;

comment on function private.pode_decidir_etapa(uuid) is 'Quem exerce o papel aprovador da etapa aberta, por papel proprio ou por delegacao vigente. A tela nao e autoridade: a policy e a RPC conferem aqui, licao da migration 20260825230000_cvrj_so_convidado_aprova.sql da Redacao.';

create or replace function private.conflito_de_interesse(p_autorizacao_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select
    exists (
      select 1 from public.autorizacoes a
      where a.id = p_autorizacao_id and a.solicitante_id = (select auth.uid())
    )
    or exists (
      select 1 from public.autorizacoes a
      join public.documento_versoes dv on dv.id = a.versao_id
      where a.id = p_autorizacao_id and dv.enviado_por = (select auth.uid())
    )
    or exists (
      select 1
      from public.autorizacao_decisoes d
      join public.autorizacao_etapas e  on e.id = d.etapa_id
      join public.autorizacao_etapas ea on ea.autorizacao_id = d.autorizacao_id and ea.estado = 'open'
      where d.autorizacao_id = p_autorizacao_id
        and d.ator_id = (select auth.uid())
        and d.decisao in ('approved','returned','rejected')
        and e.ordem < ea.ordem
        and d.decidido_em >= coalesce(ea.aberta_em, d.decidido_em) - interval '3650 days'
    );
$$;

comment on function private.conflito_de_interesse(uuid) is 'Ninguem aprova o proprio pedido, nem o documento cuja versao enviou, nem homologa a etapa que ja decidiu. Regra da Redacao (ARQUITETURA.md, secao 7.3, e migration 20260825230000), levada para dentro da RPC e da policy.';

create or replace function private.autorizacao_visivel(p_autorizacao_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1 from public.autorizacoes a
    where a.id = p_autorizacao_id
      and private.is_workspace_member(a.workspace_id)
      and (
        a.solicitante_id = (select auth.uid())
        or public.autorizar('trilha.ler_completa'::public.permissao, null)
        or public.autorizar('autorizacao.homologar'::public.permissao, a.setor_id)
        or exists (
          select 1 from public.autorizacao_etapas e
          where e.autorizacao_id = a.id
            and (
              private.tem_papel(e.papel_aprovador, e.setor_id)
              or private.delegacao_para(e.papel_aprovador, e.setor_id) is not null
            )
        )
        or exists (
          select 1 from public.assinaturas s
          where s.autorizacao_id = a.id and s.signatario_id = (select auth.uid())
        )
        or (a.estado in ('published','archived') and private.mesmo_setor(a.setor_id))
      )
  );
$$;

comment on function private.autorizacao_visivel(uuid) is 'Quem le um pedido: solicitante, aprovador designado, delegado vigente, signatario, coordenacao do setor, administrador e auditor; membros do setor so quando published ou archived. Minuta nao tramita e nao aparece, regra do SEI.';

create or replace function private.pode_montar_etapas(p_autorizacao_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1 from public.autorizacoes a
    where a.id = p_autorizacao_id
      and a.solicitante_id = (select auth.uid())
      and a.estado in ('draft','pending','changes_requested')
  );
$$;

comment on function private.pode_montar_etapas(uuid) is 'O snapshot de etapas e escrito pelo solicitante no ato da submissao, por RPC security invoker; depois disso so as transicoes e o job de prazo mexem nas etapas.';

create or replace function private.pode_retirar_autorizacao(p_autorizacao_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1 from public.autorizacoes a
    where a.id = p_autorizacao_id
      and a.solicitante_id = (select auth.uid())
      and a.estado in ('draft','pending','in_review','in_validation','changes_requested')
      and a.retirada_em is null
      and a.concluida_em is null
  );
$$;

comment on function private.pode_retirar_autorizacao(uuid) is 'Ser o solicitante e o pedido estar aberto, que e a condicao dupla da retirada na secao 10.2 do escopo, e a mesma que public.retirar_autorizacao ja conferia. Existe porque a policy autorizacao_decisoes_insert_retirada conferia so o solicitante e aceitava decisao withdrawn em pedido ja encerrado, com concluida_em preenchido: quem escrevesse direto na tabela, sem passar pela RPC, encerrava de novo um pedido approved. Defeito encontrado pela suite pgTAP do anexo 02b, na secao 7 (retirada), onde os testes vizinhos provam que a voluntaria sem segundo fator retira o proprio pedido leve e que ninguem retira o pedido de outra pessoa. A tela nunca foi autoridade: quem diz o que entra na tabela e a policy.';

create or replace function private.pode_mover_autorizacao(p_autorizacao_id uuid)
returns boolean language sql security definer set search_path = '' stable as $$
  select exists (
    select 1 from public.autorizacoes a
    where a.id = p_autorizacao_id
      and private.is_workspace_member(a.workspace_id)
      and (
        (a.solicitante_id = (select auth.uid())
          and a.estado in ('draft','pending','in_review','in_validation','changes_requested','approved','signing'))
        or exists (
          select 1 from public.autorizacao_etapas e
          where e.autorizacao_id = a.id and e.estado = 'open' and private.pode_decidir_etapa(e.id)
        )
        or public.autorizar('operacao.administrar'::public.permissao, null)
      )
  );
$$;

comment on function private.pode_mover_autorizacao(uuid) is 'Quem pode mudar o cabecalho do pedido: solicitante enquanto o pedido nao fechou, aprovador da etapa aberta e administrador.';

revoke all on function private.tem_papel(text, uuid)             from public, anon;
revoke all on function private.delegacao_para(text, uuid)        from public, anon;
revoke all on function private.pode_decidir_etapa(uuid)          from public, anon;
revoke all on function private.conflito_de_interesse(uuid)       from public, anon;
revoke all on function private.autorizacao_visivel(uuid)         from public, anon;
revoke all on function private.pode_montar_etapas(uuid)          from public, anon;
revoke all on function private.pode_retirar_autorizacao(uuid)    from public, anon;
revoke all on function private.pode_mover_autorizacao(uuid)      from public, anon;
grant execute on function private.tem_papel(text, uuid)        to authenticated;
grant execute on function private.delegacao_para(text, uuid)   to authenticated;
grant execute on function private.pode_decidir_etapa(uuid)     to authenticated;
grant execute on function private.conflito_de_interesse(uuid)  to authenticated;
grant execute on function private.autorizacao_visivel(uuid)    to authenticated;
grant execute on function private.pode_montar_etapas(uuid)     to authenticated;
grant execute on function private.pode_retirar_autorizacao(uuid) to authenticated;
grant execute on function private.pode_mover_autorizacao(uuid) to authenticated;

-- ============================================================================
-- 12. RLS e GRANTs das tabelas de autorizacao
-- ============================================================================

alter table public.autorizacoes         enable row level security;
alter table public.autorizacao_etapas   enable row level security;
alter table public.autorizacao_decisoes enable row level security;
alter table public.assinaturas          enable row level security;

-- autorizacoes
create policy autorizacoes_select_envolvido on public.autorizacoes for select to authenticated
  using ((select private.autorizacao_visivel(id)));

create policy autorizacoes_insert_solicitante on public.autorizacoes for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and solicitante_id = (select auth.uid())
    and (select public.autorizar('autorizacao.abrir'::public.permissao, setor_id))
    and estado in ('draft','pending')
    and automatica = false
    and retirada_em is null
    and concluida_em is null
    and publicada_em is null
    and consultas_publicas = 0
  );

create policy autorizacoes_update_envolvido on public.autorizacoes for update to authenticated
  using ((select private.pode_mover_autorizacao(id)))
  with check ((select private.pode_mover_autorizacao(id)));

revoke all on table public.autorizacoes from public, anon;
grant select, insert, update on table public.autorizacoes to authenticated;

drop trigger if exists autorizacoes_toca_atualizado_em on public.autorizacoes;
create trigger autorizacoes_toca_atualizado_em
  before update on public.autorizacoes
  for each row execute function public.tocar_atualizado_em();

-- autorizacao_etapas
create policy autorizacao_etapas_select_envolvido on public.autorizacao_etapas for select to authenticated
  using ((select private.autorizacao_visivel(autorizacao_id)));

create policy autorizacao_etapas_insert_snapshot on public.autorizacao_etapas for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and (select private.pode_montar_etapas(autorizacao_id))
    and estado = 'waiting'
    and fechada_em is null
    and fechada_por is null
  );

create policy autorizacao_etapas_update_decisor on public.autorizacao_etapas for update to authenticated
  using (
    (select private.pode_decidir_etapa(id))
    or (select private.pode_mover_autorizacao(autorizacao_id))
  )
  with check (
    (select private.pode_decidir_etapa(id))
    or (select private.pode_mover_autorizacao(autorizacao_id))
  );

revoke all on table public.autorizacao_etapas from public, anon;
grant select, insert, update on table public.autorizacao_etapas to authenticated;

-- autorizacao_decisoes
create policy autorizacao_decisoes_select_envolvido on public.autorizacao_decisoes for select to authenticated
  using ((select private.autorizacao_visivel(autorizacao_id)));

create policy autorizacao_decisoes_insert_decisor on public.autorizacao_decisoes for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and ator_id = (select auth.uid())
    and decisao in ('approved','returned','rejected')
    and (select private.pode_decidir_etapa(etapa_id))
    and not (select private.conflito_de_interesse(autorizacao_id))
    and (select private.exige_aal2())
  );

create policy autorizacao_decisoes_insert_retirada on public.autorizacao_decisoes for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and ator_id = (select auth.uid())
    and decisao = 'withdrawn'
    and papel_exercido = 'solicitante'
    and (select private.pode_retirar_autorizacao(autorizacao_id))
  );

comment on policy autorizacao_decisoes_insert_retirada on public.autorizacao_decisoes is
  'Retirada nao e decisao: e ato do proprio solicitante sobre o proprio pedido aberto, com decisao withdrawn e papel_exercido solicitante. Fica de proposito sem private.exige_aal2(): voluntario sem papel de aprovacao nao e obrigado a ativar TOTP e, com a exigencia, abriria um pedido leve e nunca conseguiria retira-lo, recebendo erro de RLS em vez de mensagem de produto. O segundo fator continua exigido em autorizacao_decisoes_insert_decisor. A condicao do pedido estar aberto entrou por defeito encontrado pela suite pgTAP do anexo 02b, na secao 7 (retirada): a policy conferia so ser o solicitante, e uma decisao withdrawn entrava em pedido approved, ja com concluida_em preenchido, bastando escrever direto na tabela sem passar por public.retirar_autorizacao. A secao 10.2 do escopo diz que a policy confere ser o solicitante e o pedido estar aberto, e e a policy, nao a tela, quem decide o que entra. A dupla conferencia vive em private.pode_retirar_autorizacao, com a mesma lista de estados da RPC.';

revoke all on table public.autorizacao_decisoes from public, anon;
grant select, insert on table public.autorizacao_decisoes to authenticated;

-- assinaturas
create policy assinaturas_select_envolvido on public.assinaturas for select to authenticated
  using (
    signatario_id = (select auth.uid())
    or (select private.autorizacao_visivel(autorizacao_id))
  );

create policy assinaturas_insert_signatario on public.assinaturas for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and signatario_id = (select auth.uid())
    and (select private.exige_aal2())
    and conferido_por is null
    and resultado_validador is null
  );

create policy assinaturas_update_signatario on public.assinaturas for update to authenticated
  using (signatario_id = (select auth.uid()) and estado in ('pending','generated','uploaded'))
  with check (signatario_id = (select auth.uid()) and (select private.exige_aal2()));

create policy assinaturas_update_conferente on public.assinaturas for update to authenticated
  using (
    signatario_id <> (select auth.uid())
    and (select public.autorizar('assinatura.conferir'::public.permissao, null))
  )
  with check (
    signatario_id <> (select auth.uid())
    and (select public.autorizar('assinatura.conferir'::public.permissao, null))
    and (select private.exige_aal2())
  );

revoke all on table public.assinaturas from public, anon;
grant select, insert on table public.assinaturas to authenticated;
-- Grant por coluna: o signatario sobe o PDF assinado, o conferente registra o
-- resultado do validador, e nenhum dos dois toca hash_arquivo, nivel ou codigo.
grant update (estado, hash_pdf_assinado, pdf_assinado_path, hash_confere,
              resultado_validador, relatorio_validador_path, conferido_por,
              conferido_em, certificado_emissor, assinado_em)
  on table public.assinaturas to authenticated;

create or replace function public.proteger_evidencia_assinatura()
returns trigger language plpgsql set search_path = '' as $$
begin
  if new.workspace_id       is distinct from old.workspace_id
     or new.autorizacao_id  is distinct from old.autorizacao_id
     or new.signatario_id   is distinct from old.signatario_id
     or new.nivel           is distinct from old.nivel
     or new.metodo          is distinct from old.metodo
     or new.hash_arquivo    is distinct from old.hash_arquivo
     or new.hash_pdf_gerado is distinct from old.hash_pdf_gerado
     or new.codigo_verificacao is distinct from old.codigo_verificacao
     or new.criado_em       is distinct from old.criado_em then
    raise exception 'Evidencia de assinatura e imutavel: corrigir e gerar nova assinatura.'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

comment on function public.proteger_evidencia_assinatura() is 'A evidencia (nivel, metodo, hashes e codigo) nunca muda depois de gravada, no espirito do DocumentAuditLog do Documenso. Corrigir e gerar nova assinatura, como corrigir documento e subir nova versao na biblioteca.';

drop trigger if exists assinaturas_protege_evidencia on public.assinaturas;
create trigger assinaturas_protege_evidencia
  before update on public.assinaturas
  for each row execute function public.proteger_evidencia_assinatura();

-- ============================================================================
-- 13. Transicoes de estado: RPCs security invoker
-- ============================================================================

create or replace function public.abrir_autorizacao(
  p_tipo_ato    public.tipo_ato,
  p_objeto_tipo text,
  p_objeto_id   uuid,
  p_setor_id    uuid,
  p_dados       jsonb default '{}'
) returns uuid
language plpgsql security invoker set search_path = '' as $$
declare
  v_regra   public.autorizacao_regras%rowtype;
  v_id      uuid;
  v_etapa   jsonb;
  v_setor   uuid;
  v_rodada  smallint;
  v_sequencia smallint;
  v_despesa uuid;
  v_prazo   smallint;
  v_primeira uuid;
begin
  select * into v_regra
    from public.autorizacao_regras r
   where r.tipo_ato = p_tipo_ato and r.ativo
   limit 1;
  if not found then
    raise exception 'Nao ha regra ativa para este tipo de ato.' using errcode = 'P0002';
  end if;

  -- Lei 9.608: so se ressarce despesa expressamente autorizada antes do gasto.
  if p_tipo_ato = 'ressarcimento' then
    v_despesa := nullif(coalesce(p_dados, '{}') ->> 'autorizacao_despesa_id', '')::uuid;
    if v_despesa is null then
      raise exception 'Ressarcimento exige em dados.autorizacao_despesa_id o pedido de autorizacao de despesa previo.'
        using errcode = '22023';
    end if;
    if not exists (
      select 1 from public.autorizacoes ad
       where ad.id = v_despesa
         and ad.tipo_ato = 'autorizacao_despesa'
         and ad.estado in ('approved','auto_approved')
         and ad.retirada_em is null
         and (ad.arquivar_em is null or ad.arquivar_em > now())
    ) then
      raise exception 'A autorizacao de despesa informada nao esta aprovada e vigente.' using errcode = '42501';
    end if;
  end if;

  -- Dois contadores distintos: sequencia_do_objeto conta os pedidos ja abertos
  -- sobre o mesmo objeto e sustenta a unicidade; rodada conta as submissoes
  -- dentro deste pedido e por isso nasce em 1.
  select coalesce(max(a.sequencia_do_objeto), 0) + 1 into v_sequencia
    from public.autorizacoes a
   where a.objeto_tipo = p_objeto_tipo and a.objeto_id = p_objeto_id;
  v_rodada := 1;

  -- A chave nasce aqui, e nao por returning. Insert com returning tambem passa
  -- pela policy de select da tabela, e autorizacoes_select_envolvido chama
  -- private.autorizacao_visivel(id), que procura o pedido em public.autorizacoes:
  -- dentro da mesma instrucao a linha ainda nao existe para essa consulta, a
  -- regra devolvia falso e nenhum pedido nascia, nem para quem le a trilha
  -- inteira. Gerando o uuid antes, o insert dispensa o returning, a policy de
  -- insert continua sendo conferida inteira pelo Postgres e a visibilidade do
  -- pedido depois de criado fica exatamente como estava.
  v_id := pg_catalog.gen_random_uuid();

  insert into public.autorizacoes (
    id, workspace_id, tipo, tipo_ato, regra_id, objeto_tipo, objeto_id, rodada, sequencia_do_objeto,
    solicitante_id, setor_id, estado, dados, tipo_gestao,
    nivel_assinatura_exigido, arquivar_em
  )
  select v_id, v_regra.workspace_id, v_regra.tipo, p_tipo_ato, v_regra.id, p_objeto_tipo, p_objeto_id, v_rodada, v_sequencia,
         (select auth.uid()), p_setor_id,
         case when v_regra.tipo = 'document' then 'draft' else 'pending' end,
         coalesce(p_dados, '{}'), v_regra.tipo_gestao_padrao,
         coalesce(pa.nivel_exigido, 'nenhuma'::public.nivel_assinatura),
         case when v_regra.arquivar_apos_dias is null then null
              else now() + make_interval(days => v_regra.arquivar_apos_dias) end
    from (select 1) x
    left join public.politicas_assinatura pa on pa.id = v_regra.politica_assinatura_id;

  -- Snapshot das etapas: regra alterada depois nao muda pedido em curso.
  for v_etapa in select * from jsonb_array_elements(v_regra.etapas) loop
    v_setor := case
                 when coalesce(v_etapa->>'setor_id', 'origem') = 'origem' then p_setor_id
                 else (v_etapa->>'setor_id')::uuid
               end;
    v_prazo := coalesce((v_etapa->>'prazo_dias_uteis')::smallint, v_regra.prazo_dias_uteis_padrao);
    insert into public.autorizacao_etapas (
      workspace_id, autorizacao_id, ordem, papel_aprovador, setor_id, quorum,
      prazo_dias_uteis, acao_ao_expirar, estado
    ) values (
      v_regra.workspace_id, v_id, (v_etapa->>'ordem')::smallint, v_etapa->>'papel_aprovador',
      v_setor, coalesce((v_etapa->>'quorum')::smallint, 1), v_prazo,
      coalesce(v_etapa->>'acao_ao_expirar', 'escalate'), 'waiting'
    );
  end loop;

  if v_regra.tipo = 'light' then
    update public.autorizacao_etapas e
       set estado = 'open', aberta_em = now(),
           prazo_em = public.somar_dias_uteis(now(), e.prazo_dias_uteis)
     where e.autorizacao_id = v_id and e.ordem = 1
    returning e.id into v_primeira;

    update public.autorizacoes a
       set etapa_atual = 1,
           prazo_em = (select e.prazo_em from public.autorizacao_etapas e where e.id = v_primeira)
     where a.id = v_id;

    perform auditoria.registrar_evento(
      v_regra.workspace_id, v_regra.fluxo_codigo, 'autorizacoes', v_id,
      'autorizacao.solicitada', 'solicitante', v_rodada::integer,
      null, jsonb_build_object('estado', 'pending', 'rodada', v_rodada, 'tipo_ato', p_tipo_ato::text)
    );
    perform auditoria.registrar_evento(
      v_regra.workspace_id, v_regra.fluxo_codigo, 'autorizacao_etapas', v_primeira,
      'autorizacao.etapa_aberta', 'solicitante', v_rodada::integer,
      null, jsonb_build_object('estado', 'open', 'ordem', 1)
    );
  end if;

  return v_id;
end;
$$;

comment on function public.abrir_autorizacao(public.tipo_ato, text, uuid, uuid, jsonb) is 'Abre o pedido e copia as etapas da regra (snapshot). Tramite leve ja nasce com a etapa 1 aberta; documento nasce draft porque minuta nao tramita (SEI). security invoker: o RLS continua valendo dentro da funcao, como nas RPCs da Redacao. A chave do pedido passou a ser gerada antes do insert, em vez de vir por returning id, por defeito encontrado pela suite pgTAP do anexo 02b, teste 93 (a solicitante abre um pedido leve pela funcao de abertura do tramite): num insert com returning o Postgres aplica tambem a policy de select, e autorizacoes_select_envolvido chama private.autorizacao_visivel(id), que procura o pedido na propria tabela; dentro da mesma instrucao a linha ainda nao existe para essa consulta, a regra devolvia falso e nenhum pedido nascia, nem para quem tem trilha.ler_completa. Sem o returning, autorizacoes_insert_solicitante continua sendo conferida inteira pelo banco e a visibilidade do pedido depois de criado nao mudou.';

create or replace function public.submeter_documento(
  p_autorizacao_id uuid,
  p_versao_id      uuid
) returns text
language plpgsql security invoker set search_path = '' as $$
declare
  v_a       public.autorizacoes%rowtype;
  v_regra   public.autorizacao_regras%rowtype;
  v_hash    text;
  v_doc     uuid;
  v_primeira uuid;
  v_rodada  smallint;
begin
  select * into v_a from public.autorizacoes where id = p_autorizacao_id;
  if not found then
    raise exception 'Pedido nao encontrado ou sem permissao.' using errcode = 'P0002';
  end if;
  if v_a.tipo <> 'document' then
    raise exception 'Submissao de versao vale so para tramite por documento.' using errcode = '22023';
  end if;
  if v_a.estado not in ('draft','changes_requested') then
    raise exception 'Pedido em % nao admite submissao.', v_a.estado using errcode = '22023';
  end if;
  if v_a.solicitante_id <> (select auth.uid()) then
    raise exception 'So o solicitante submete a versao.' using errcode = '42501';
  end if;
  if not (select private.exige_aal2()) then
    raise exception 'Submissao exige sessao com segundo fator verificado.' using errcode = '42501';
  end if;

  select dv.hash_sha256, dv.documento_id into v_hash, v_doc
    from public.documento_versoes dv where dv.id = p_versao_id;
  if v_hash is null then
    raise exception 'Versao nao encontrada ou sem permissao.' using errcode = 'P0002';
  end if;
  if v_a.objeto_tipo = 'documentos' and v_doc <> v_a.objeto_id then
    raise exception 'A versao nao pertence ao documento deste pedido.' using errcode = '22023';
  end if;

  select * into v_regra from public.autorizacao_regras where id = v_a.regra_id;

  v_rodada := case when v_a.estado = 'changes_requested' then v_a.rodada + 1 else v_a.rodada end;

  -- Rodada nova reutiliza as mesmas etapas: aberta_em marca a rodada corrente,
  -- e uma decisao so conta quando decidido_em e posterior a ela.
  update public.autorizacao_etapas
     set estado = 'waiting', aberta_em = null, prazo_em = null,
         lembrete_enviado_em = null, escalada_em = null,
         fechada_em = null, fechada_por = null
   where autorizacao_id = v_a.id;

  update public.autorizacao_etapas e
     set estado = 'open', aberta_em = now(),
         prazo_em = public.somar_dias_uteis(now(), e.prazo_dias_uteis)
   where e.autorizacao_id = v_a.id and e.ordem = 1
  returning e.id into v_primeira;

  update public.autorizacoes a
     set estado = 'in_review',
         rodada = v_rodada,
         versao_id = p_versao_id,
         hash_arquivo_submissao = v_hash,
         etapa_atual = 1,
         motivo_negacao = null,
         prazo_em = (select e.prazo_em from public.autorizacao_etapas e where e.id = v_primeira)
   where a.id = v_a.id;

  perform auditoria.registrar_evento(
    v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacoes', v_a.id,
    'documento.submetido', 'solicitante', v_rodada::integer,
    jsonb_build_object('estado', v_a.estado, 'rodada', v_a.rodada),
    jsonb_build_object('estado', 'in_review', 'rodada', v_rodada, 'versao_id', p_versao_id),
    v_hash
  );
  perform auditoria.registrar_evento(
    v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacao_etapas', v_primeira,
    'autorizacao.etapa_aberta', 'solicitante', v_rodada::integer,
    null, jsonb_build_object('estado', 'open', 'ordem', 1), v_hash
  );

  return 'in_review';
end;
$$;

comment on function public.submeter_documento(uuid, uuid) is 'Congela a versao e o hash na submissao e abre a etapa 1. Devolucao seguida de nova submissao abre rodada nova (progressivo do Jorvik) e nunca reabre a anterior.';

create or replace function public.decidir_autorizacao(
  p_autorizacao_id uuid,
  p_decisao        text,
  p_motivo         text default null,
  p_hash_versao    text default null,
  p_ip             inet default null,
  p_user_agent     text default null
) returns text
language plpgsql security invoker set search_path = '' as $$
declare
  v_a         public.autorizacoes%rowtype;
  v_regra     public.autorizacao_regras%rowtype;
  v_etapa     public.autorizacao_etapas%rowtype;
  v_proxima   public.autorizacao_etapas%rowtype;
  v_hash      text;
  v_delegacao uuid;
  v_aal       text;
  v_aprovadas integer;
  v_estado    text;
  v_acao      text;
  v_hash_dec  text;
  v_totp_em   timestamptz;
  v_prazo_em  timestamptz;
  v_linhas    integer;
begin
  if p_decisao not in ('approved','returned','rejected') then
    raise exception 'Decisao invalida: %', p_decisao using errcode = '22023';
  end if;

  select * into v_a from public.autorizacoes where id = p_autorizacao_id;
  if not found then
    raise exception 'Pedido nao encontrado ou sem permissao.' using errcode = 'P0002';
  end if;
  if v_a.estado not in ('pending','in_review','in_validation') then
    raise exception 'Pedido em % nao admite decisao.', v_a.estado using errcode = '22023';
  end if;
  if v_a.tipo = 'light' and p_decisao = 'returned' then
    raise exception 'Tramite leve nao tem devolucao: aprove ou negue.' using errcode = '22023';
  end if;
  if p_decisao in ('returned','rejected') and coalesce(btrim(p_motivo), '') = '' then
    raise exception 'Devolucao e negacao exigem motivo.' using errcode = '22023';
  end if;

  select * into v_etapa from public.autorizacao_etapas e
   where e.autorizacao_id = v_a.id and e.estado = 'open'
   order by e.ordem limit 1;
  if not found then
    raise exception 'Nao ha etapa aberta neste pedido.' using errcode = '42501';
  end if;
  if not (select private.pode_decidir_etapa(v_etapa.id)) then
    raise exception 'Voce nao exerce o papel % no setor desta etapa.', v_etapa.papel_aprovador
      using errcode = '42501';
  end if;
  if (select private.conflito_de_interesse(v_a.id)) then
    raise exception 'Ninguem decide o proprio pedido, nem homologa a etapa que ja decidiu.'
      using errcode = '42501';
  end if;
  if not (select private.exige_aal2()) then
    raise exception 'Decisao exige sessao com segundo fator verificado.' using errcode = '42501';
  end if;

  -- Janela de reautenticacao lida da claim amr do JWT corrente, no elemento de
  -- metodo totp. Nao se le public.profiles.mfa_verificado_em porque a policy
  -- profiles_update_self da Redacao deixa a propria pessoa gravar essa coluna,
  -- e prova de fator nao pode vir de campo que o interessado escreve. Sao os
  -- mesmos 900 segundos de public.assinar_aceite_interno.
  v_totp_em := (
    select to_timestamp((e ->> 'timestamp')::bigint)
      from jsonb_array_elements(coalesce((select auth.jwt() -> 'amr'), '[]'::jsonb)) e
     where e ->> 'method' = 'totp'
     order by (e ->> 'timestamp')::bigint desc
     limit 1
  );
  if v_totp_em is null or v_totp_em < now() - interval '900 seconds' then
    raise exception 'Refaca a verificacao do segundo fator: a ultima tem mais de 900 segundos.'
      using errcode = '42501';
  end if;

  if exists (
    select 1 from public.autorizacao_decisoes d
    where d.etapa_id = v_etapa.id
      and d.ator_id = (select auth.uid())
      and d.decidido_em >= v_etapa.aberta_em
  ) then
    raise exception 'Voce ja decidiu esta etapa nesta rodada.' using errcode = '23505';
  end if;

  select * into v_regra from public.autorizacao_regras where id = v_a.regra_id;

  -- Regra do etag: nao se decide sobre arquivo alterado.
  if v_a.tipo = 'document' then
    select dv.hash_sha256 into v_hash from public.documento_versoes dv where dv.id = v_a.versao_id;
    if v_hash is distinct from v_a.hash_arquivo_submissao then
      raise exception 'O arquivo mudou depois da submissao: gere nova versao e submeta de novo.'
        using errcode = '40001';
    end if;
    if p_hash_versao is not null and p_hash_versao <> v_hash then
      raise exception 'O hash conferido na tela nao confere com o da versao tramitada.'
        using errcode = '40001';
    end if;
  end if;

  v_delegacao := (select private.delegacao_para(v_etapa.papel_aprovador, v_etapa.setor_id));
  v_aal := coalesce((select auth.jwt() ->> 'aal'), 'aal1');

  v_hash_dec := public.hash_canonico(jsonb_build_object(
    'autorizacao_id', v_a.id,
    'etapa_id',       v_etapa.id,
    'ordem',          v_etapa.ordem,
    'rodada',         v_a.rodada,
    'decisao',        p_decisao,
    'papel',          v_etapa.papel_aprovador,
    'ator_id',        (select auth.uid()),
    'hash_arquivo',   coalesce(v_hash, ''),
    'decidido_em',    to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
  ));

  insert into public.autorizacao_decisoes (
    workspace_id, autorizacao_id, etapa_id, ator_id, papel_exercido, delegacao_id,
    decisao, motivo, hash_versao, hash_decisao, aal, ip, user_agent
  ) values (
    v_a.workspace_id, v_a.id, v_etapa.id, (select auth.uid()), v_etapa.papel_aprovador, v_delegacao,
    p_decisao, p_motivo, v_hash, v_hash_dec, v_aal, p_ip, p_user_agent
  );

  if v_delegacao is not null then
    perform auditoria.registrar_evento(
      v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacao_etapas', v_etapa.id,
      'autorizacao.delegada', v_etapa.papel_aprovador, v_a.rodada::integer,
      null, jsonb_build_object('ordem', v_etapa.ordem, 'etapa_id', v_etapa.id),
      v_hash, v_hash_dec, p_ip, p_user_agent
    );
  end if;

  if p_decisao = 'approved' then
    select count(*) into v_aprovadas
      from public.autorizacao_decisoes d
     where d.etapa_id = v_etapa.id and d.decisao = 'approved'
       and d.decidido_em >= v_etapa.aberta_em;

    if v_aprovadas < v_etapa.quorum then
      perform auditoria.registrar_evento(
        v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacoes', v_a.id,
        'autorizacao.aprovada', v_etapa.papel_aprovador, v_a.rodada::integer,
        jsonb_build_object('estado', v_a.estado, 'quorum', v_etapa.quorum),
        jsonb_build_object('estado', v_a.estado, 'ordem', v_etapa.ordem),
        v_hash, v_hash_dec, p_ip, p_user_agent
      );
      return v_a.estado;
    end if;

    -- Ordem das escritas nos tres ramos: primeiro o cabecalho, depois a etapa
    -- seguinte quando houver e so por ultimo a etapa corrente. A policy
    -- autorizacoes_update_envolvido chama private.pode_mover_autorizacao, que so
    -- devolve verdadeiro para o solicitante, para quem pode decidir uma etapa
    -- ainda aberta ou para quem tem operacao.administrar: fechar a etapa antes
    -- faz o using filtrar a linha, zero linhas atualizadas e nenhuma excecao.
    select * into v_proxima from public.autorizacao_etapas e
     where e.autorizacao_id = v_a.id and e.ordem > v_etapa.ordem and e.estado = 'waiting'
     order by e.ordem limit 1;

    if found then
      v_prazo_em := public.somar_dias_uteis(now(), v_proxima.prazo_dias_uteis);
      v_estado := case when v_a.tipo = 'document' then 'in_validation' else 'pending' end;

      update public.autorizacoes a
         set estado = v_estado, etapa_atual = v_proxima.ordem, prazo_em = v_prazo_em
       where a.id = v_a.id;
      get diagnostics v_linhas = row_count;

      update public.autorizacao_etapas e
         set estado = 'open', aberta_em = now(), prazo_em = v_prazo_em
       where e.id = v_proxima.id;

      update public.autorizacao_etapas
         set estado = 'approved', fechada_em = now(), fechada_por = (select auth.uid())
       where id = v_etapa.id;

      v_acao := 'autorizacao.aprovada';
      perform auditoria.registrar_evento(
        v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacao_etapas', v_proxima.id,
        'autorizacao.etapa_aberta', v_etapa.papel_aprovador, v_a.rodada::integer,
        null, jsonb_build_object('estado', 'open', 'ordem', v_proxima.ordem),
        v_hash, v_hash_dec, p_ip, p_user_agent
      );
    else
      v_estado := case
                    when v_a.tipo = 'document' and v_a.nivel_assinatura_exigido <> 'nenhuma' then 'signing'
                    when v_a.tipo = 'document' then 'approved'
                    else 'approved'
                  end;
      update public.autorizacoes a
         set estado = v_estado, etapa_atual = null, prazo_em = null, concluida_em = now()
       where a.id = v_a.id;
      get diagnostics v_linhas = row_count;

      update public.autorizacao_etapas
         set estado = 'approved', fechada_em = now(), fechada_por = (select auth.uid())
       where id = v_etapa.id;

      v_acao := case when v_a.tipo = 'document' then 'autorizacao.homologada' else 'autorizacao.aprovada' end;
    end if;

  elsif p_decisao = 'returned' then
    v_estado := 'changes_requested';
    update public.autorizacoes a
       set estado = v_estado, etapa_atual = null, prazo_em = null
     where a.id = v_a.id;
    get diagnostics v_linhas = row_count;

    update public.autorizacao_etapas
       set estado = 'returned', fechada_em = now(), fechada_por = (select auth.uid())
     where id = v_etapa.id;
    v_acao := 'autorizacao.devolvida';

  else
    v_estado := case when v_a.tipo = 'document' then 'rejected' else 'denied' end;
    update public.autorizacoes a
       set estado = v_estado, etapa_atual = null, prazo_em = null,
           motivo_negacao = p_motivo, concluida_em = now()
     where a.id = v_a.id;
    get diagnostics v_linhas = row_count;

    update public.autorizacao_etapas
       set estado = 'rejected', fechada_em = now(), fechada_por = (select auth.uid())
     where id = v_etapa.id;
    v_acao := 'autorizacao.negada';
  end if;

  -- Conferencia de fim: o cabecalho tem de ter sido movido, e exatamente uma
  -- linha. Regressao que faca o RLS filtrar o update nao passa mais em silencio.
  if v_linhas is distinct from 1 then
    raise exception 'A decisao nao moveu o pedido: % linhas atualizadas no cabecalho.',
      coalesce(v_linhas, 0) using errcode = '42501';
  end if;

  perform auditoria.registrar_evento(
    v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacoes', v_a.id,
    v_acao, v_etapa.papel_aprovador, v_a.rodada::integer,
    jsonb_build_object('estado', v_a.estado, 'etapa_atual', v_a.etapa_atual),
    jsonb_build_object('estado', v_estado, 'ordem', v_etapa.ordem),
    v_hash, v_hash_dec, p_ip, p_user_agent
  );

  return v_estado;
end;
$$;
comment on function public.decidir_autorizacao(uuid, text, text, text, inet, text) is 'Aprovar, devolver, negar e homologar em uma so transicao guardada, no molde de validateWorkflow do XWiki Publication Workflow. Recusa quem nao exerce o papel da etapa aberta, quem tem conflito de interesse e quem decide sobre arquivo alterado (regra do etag do Nextcloud Approval); grava decisao, mudanca de estado e evento na mesma transacao. Tela nao e autoridade: botao desabilitado e conforto, a RPC e a cerca.';

create or replace function public.retirar_autorizacao(
  p_autorizacao_id uuid,
  p_motivo         text default null
) returns text
language plpgsql security invoker set search_path = '' as $$
declare
  v_a     public.autorizacoes%rowtype;
  v_regra public.autorizacao_regras%rowtype;
  v_etapa public.autorizacao_etapas%rowtype;
  v_hash_dec text;
begin
  select * into v_a from public.autorizacoes where id = p_autorizacao_id;
  if not found then
    raise exception 'Pedido nao encontrado ou sem permissao.' using errcode = 'P0002';
  end if;
  if v_a.solicitante_id <> (select auth.uid()) then
    raise exception 'So o solicitante retira o proprio pedido.' using errcode = '42501';
  end if;
  if v_a.estado not in ('draft','pending','in_review','in_validation','changes_requested') then
    raise exception 'Pedido em % nao pode mais ser retirado.', v_a.estado using errcode = '22023';
  end if;

  select * into v_regra from public.autorizacao_regras where id = v_a.regra_id;
  select * into v_etapa from public.autorizacao_etapas e
   where e.autorizacao_id = v_a.id and e.estado = 'open' order by e.ordem limit 1;

  v_hash_dec := public.hash_canonico(jsonb_build_object(
    'autorizacao_id', v_a.id, 'rodada', v_a.rodada, 'decisao', 'withdrawn',
    'ator_id', (select auth.uid()),
    'decidido_em', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
  ));

  if v_etapa.id is not null then
    insert into public.autorizacao_decisoes (
      workspace_id, autorizacao_id, etapa_id, ator_id, papel_exercido,
      decisao, motivo, hash_decisao, aal
    ) values (
      v_a.workspace_id, v_a.id, v_etapa.id, (select auth.uid()), 'solicitante',
      'withdrawn', p_motivo, v_hash_dec, coalesce((select auth.jwt() ->> 'aal'), 'aal1')
    );
    update public.autorizacao_etapas
       set estado = 'skipped', fechada_em = now(), fechada_por = (select auth.uid())
     where autorizacao_id = v_a.id and estado in ('open','waiting');
  end if;

  update public.autorizacoes a
     set estado = 'withdrawn', retirada_em = now(), etapa_atual = null,
         prazo_em = null, concluida_em = now()
   where a.id = v_a.id;

  perform auditoria.registrar_evento(
    v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacoes', v_a.id,
    'autorizacao.retirada', 'solicitante', v_a.rodada::integer,
    jsonb_build_object('estado', v_a.estado),
    jsonb_build_object('estado', 'withdrawn'),
    v_a.hash_arquivo_submissao, v_hash_dec
  );

  return 'withdrawn';
end;
$$;

comment on function public.retirar_autorizacao(uuid, text) is 'Retirada pelo solicitante enquanto o pedido nao fechou, como autorizzazioni_ritira do Jorvik. Nova tentativa e nova rodada, nunca reabertura da anterior.';

create or replace function public.assinar_aceite_interno(
  p_autorizacao_id uuid,
  p_versao_id      uuid default null,
  p_hash_arquivo   text default null,
  p_ip             inet default null,
  p_user_agent     text default null
) returns uuid
language plpgsql security invoker set search_path = '' as $$
declare
  v_a        public.autorizacoes%rowtype;
  v_regra    public.autorizacao_regras%rowtype;
  v_hash     text;
  v_doc      uuid;
  v_id       uuid;
  v_hash_dec text;
  v_totp_em  timestamptz;
begin
  select * into v_a from public.autorizacoes where id = p_autorizacao_id;
  if not found then
    raise exception 'Pedido nao encontrado ou sem permissao.' using errcode = 'P0002';
  end if;
  if v_a.estado not in ('approved','signing','pending') then
    raise exception 'Pedido em % nao admite aceite.', v_a.estado using errcode = '22023';
  end if;
  if v_a.nivel_assinatura_exigido not in ('simples','nenhuma') then
    raise exception 'Este ato exige assinatura % : o aceite interno nao serve.',
      v_a.nivel_assinatura_exigido using errcode = '42501';
  end if;
  if not (select private.exige_aal2()) then
    raise exception 'O aceite interno exige reautenticacao com o segundo fator.' using errcode = '42501';
  end if;

  -- Janela de reautenticacao lida da claim amr do JWT corrente, no elemento de
  -- metodo totp. Nao se le public.profiles.mfa_verificado_em porque a policy
  -- profiles_update_self da Redacao deixa a propria pessoa gravar essa coluna,
  -- e prova de fator nao pode vir de campo que o interessado escreve. Sao os
  -- mesmos 900 segundos de public.decidir_autorizacao.
  v_totp_em := (
    select to_timestamp((e ->> 'timestamp')::bigint)
      from jsonb_array_elements(coalesce((select auth.jwt() -> 'amr'), '[]'::jsonb)) e
     where e ->> 'method' = 'totp'
     order by (e ->> 'timestamp')::bigint desc
     limit 1
  );
  if v_totp_em is null or v_totp_em < now() - interval '900 seconds' then
    raise exception 'Refaca a verificacao do segundo fator: a ultima tem mais de 900 segundos.'
      using errcode = '42501';
  end if;

  if p_versao_id is not null then
    select dv.hash_sha256, dv.documento_id into v_hash, v_doc
      from public.documento_versoes dv where dv.id = p_versao_id;
    if v_hash is null then
      raise exception 'Versao nao encontrada ou sem permissao.' using errcode = 'P0002';
    end if;
    if p_hash_arquivo is not null and p_hash_arquivo <> v_hash then
      raise exception 'O hash conferido na tela nao confere com o da versao.' using errcode = '40001';
    end if;
  else
    -- Aceite de tramite leve: assina-se o JSON canonico da propria decisao.
    v_hash := public.hash_canonico(jsonb_build_object(
      'autorizacao_id', v_a.id, 'tipo_ato', v_a.tipo_ato::text,
      'rodada', v_a.rodada, 'dados', v_a.dados
    ));
  end if;

  select * into v_regra from public.autorizacao_regras where id = v_a.regra_id;

  insert into public.assinaturas (
    workspace_id, autorizacao_id, documento_id, versao_id, signatario_id,
    nivel, metodo, estado, hash_arquivo, aal, ip, user_agent, assinado_em
  ) values (
    v_a.workspace_id, v_a.id, v_doc, p_versao_id, (select auth.uid()),
    'simples', 'totp', 'completed', v_hash, 'aal2', p_ip, p_user_agent, now()
  )
  returning id into v_id;

  v_hash_dec := public.hash_canonico(jsonb_build_object(
    'assinatura_id', v_id, 'autorizacao_id', v_a.id, 'nivel', 'simples',
    'ator_id', (select auth.uid()), 'hash_arquivo', v_hash,
    'assinado_em', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
  ));

  perform auditoria.registrar_evento(
    v_a.workspace_id, 'F03', 'assinaturas', v_id,
    'assinatura.aceite_registrado', 'signatario', v_a.rodada::integer,
    null, jsonb_build_object('nivel_assinatura', 'simples', 'autorizacao_id', v_a.id),
    v_hash, v_hash_dec, p_ip, p_user_agent
  );

  return v_id;
end;
$$;

comment on function public.assinar_aceite_interno(uuid, uuid, text, inet, text) is 'Assinatura simples da Lei 14.063/2020, art. 4: reautenticacao com MFA TOTP (private.exige_aal2() e, na claim amr do JWT, elemento de metodo totp com no maximo 900 segundos), SHA-256 do arquivo ou do JSON canonico, data do servidor, IP e agente. A janela foi igualada a de public.decidir_autorizacao porque a assinatura acontece em campo, com sinal ruim, e a idade do fator sai do JWT porque public.profiles.mfa_verificado_em e gravavel pela policy profiles_update_self da Redacao. Entre particulares o fundamento e a MP 2.200-2, art. 10, parag. 2, com o termo de adesao reconhecendo as decisoes na intranet como manifestacao de vontade.';

create or replace function public.publicar_autorizacao(p_autorizacao_id uuid)
returns text
language plpgsql security invoker set search_path = '' as $$
declare
  v_a      public.autorizacoes%rowtype;
  v_regra  public.autorizacao_regras%rowtype;
  v_doc    uuid;
  v_status text;
  v_linhas integer;
begin
  select * into v_a from public.autorizacoes where id = p_autorizacao_id;
  if not found then
    raise exception 'Pedido nao encontrado ou sem permissao.' using errcode = 'P0002';
  end if;
  if v_a.tipo <> 'document' then
    raise exception 'So tramite de documento chega a published.' using errcode = '22023';
  end if;
  if v_a.estado not in ('approved','signing') then
    raise exception 'Pedido em % nao pode ser publicado.', v_a.estado using errcode = '22023';
  end if;
  if not (select private.exige_aal2()) then
    raise exception 'A publicacao exige sessao com o segundo fator verificado.' using errcode = '42501';
  end if;

  select * into v_regra from public.autorizacao_regras where id = v_a.regra_id;

  if not ((select public.autorizar('autorizacao.homologar'::public.permissao, v_a.setor_id))
          or v_a.solicitante_id = (select auth.uid())) then
    raise exception 'So quem homologa, ou o proprio solicitante quando a regra assim o define, publica o ato.'
      using errcode = '42501';
  end if;

  update public.autorizacoes a
     set estado = 'published', publicada_em = now(), etapa_atual = null, prazo_em = null,
         concluida_em = coalesce(a.concluida_em, now()),
         arquivar_em = case when v_regra.arquivar_apos_dias is null then a.arquivar_em
                            else now() + make_interval(days => v_regra.arquivar_apos_dias) end
   where a.id = v_a.id;
  get diagnostics v_linhas = row_count;
  if v_linhas is distinct from 1 then
    raise exception 'A publicacao nao moveu o pedido: % linhas atualizadas no cabecalho.',
      coalesce(v_linhas, 0) using errcode = '42501';
  end if;

  -- Documento correspondente: de minuta a vigente pelo marcador de sessao que
  -- public.documentos_guarda_colunas() reconhece como RPC de publicacao.
  if v_a.objeto_tipo = 'documentos' then
    v_doc := v_a.objeto_id;
  elsif v_a.versao_id is not null then
    select dv.documento_id into v_doc from public.documento_versoes dv where dv.id = v_a.versao_id;
  end if;

  if v_doc is not null then
    select d.status into v_status from public.documentos d where d.id = v_doc;
    if v_status is null then
      raise exception 'Documento nao encontrado ou sem permissao.' using errcode = 'P0002';
    end if;
    if v_status = 'draft' then
      perform set_config('cvrj.publicacao_autorizada', 'on', true);
      update public.documentos d set status = 'current' where d.id = v_doc and d.status = 'draft';
      get diagnostics v_linhas = row_count;
      perform set_config('cvrj.publicacao_autorizada', 'off', true);
      if v_linhas is distinct from 1 then
        raise exception 'A minuta nao foi levada a vigente: % linhas atualizadas em documentos.',
          coalesce(v_linhas, 0) using errcode = '42501';
      end if;
    end if;
  end if;

  perform auditoria.registrar_evento(
    v_a.workspace_id, v_regra.fluxo_codigo, 'autorizacoes', v_a.id,
    'documento.publicado', 'homologador', v_a.rodada::integer,
    jsonb_build_object('estado', v_a.estado),
    jsonb_build_object('estado', 'published'),
    v_a.hash_arquivo_submissao
  );

  return 'published';
end;
$$;

comment on function public.publicar_autorizacao(uuid) is 'Transicao de entrada do estado published, que constava do check e nenhuma funcao alcancava: leva o pedido de signing ou approved para published, carimba publicada_em, calcula arquivar_em por public.autorizacao_regras.arquivar_apos_dias, leva o documento correspondente de draft para current pelo marcador de sessao cvrj.publicacao_autorizada e registra documento.publicado. Exige private.exige_aal2() e papel de homologacao ou o proprio solicitante, conforme a regra. Documento nunca e aprovado nem publicado por decurso de prazo: publicar e sempre ato de pessoa.';

revoke all on function public.abrir_autorizacao(public.tipo_ato, text, uuid, uuid, jsonb) from public, anon;
revoke all on function public.submeter_documento(uuid, uuid)                               from public, anon;
revoke all on function public.decidir_autorizacao(uuid, text, text, text, inet, text)      from public, anon;
revoke all on function public.retirar_autorizacao(uuid, text)                              from public, anon;
revoke all on function public.assinar_aceite_interno(uuid, uuid, text, inet, text)         from public, anon;
revoke all on function public.publicar_autorizacao(uuid)                                   from public, anon;
grant execute on function public.abrir_autorizacao(public.tipo_ato, text, uuid, uuid, jsonb) to authenticated;
grant execute on function public.submeter_documento(uuid, uuid)                              to authenticated;
grant execute on function public.decidir_autorizacao(uuid, text, text, text, inet, text)     to authenticated;
grant execute on function public.retirar_autorizacao(uuid, text)                             to authenticated;
grant execute on function public.assinar_aceite_interno(uuid, uuid, text, inet, text)        to authenticated;
grant execute on function public.publicar_autorizacao(uuid)                                  to authenticated;

-- ============================================================================
-- 14. Prazo, lembrete e escalonamento (job)
-- ============================================================================

create or replace function public.processar_prazos_autorizacao()
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  r        record;
  v_proxima public.autorizacao_etapas%rowtype;
  v_mexidas integer := 0;
  v_hash_dec text;
  v_papel_homologa text;
  v_prazo_novo timestamptz;
  v_estado_venc text;
begin
  -- Lembrete: no dia util anterior ao vencimento e no dia do vencimento.
  for r in
    select e.*, a.workspace_id as ws, a.rodada, reg.fluxo_codigo
      from public.autorizacao_etapas e
      join public.autorizacoes a           on a.id = e.autorizacao_id
      join public.autorizacao_regras reg   on reg.id = a.regra_id
     where e.estado = 'open'
       and e.prazo_em is not null
       and e.prazo_em <= now() + interval '1 day'
       and e.prazo_em > now()
       and (e.lembrete_enviado_em is null or e.lembrete_enviado_em < now() - interval '20 hours')
  loop
    update public.autorizacao_etapas set lembrete_enviado_em = now() where id = r.id;
    perform auditoria.registrar_evento_do_sistema(
      r.ws, r.fluxo_codigo, 'autorizacao_etapas', r.id,
      'autorizacao.lembrete_enviado', r.rodada::integer,
      null, jsonb_build_object('ordem', r.ordem, 'prazo_em', to_char(r.prazo_em at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SSOF'))
    );
    v_mexidas := v_mexidas + 1;
  end loop;

  -- Vencidas: um dia util depois do prazo, aplica acao_ao_expirar.
  for r in
    select e.*, a.workspace_id as ws, a.tipo as tipo_pedido, a.rodada,
           a.hash_arquivo_submissao, reg.fluxo_codigo, reg.tipo_gestao_padrao
      from public.autorizacao_etapas e
      join public.autorizacoes a         on a.id = e.autorizacao_id
      join public.autorizacao_regras reg on reg.id = a.regra_id
     where e.estado = 'open'
       and e.prazo_em is not null
       and public.somar_dias_uteis(e.prazo_em, 1) <= now()
  loop
    v_hash_dec := public.hash_canonico(jsonb_build_object(
      'autorizacao_id', r.autorizacao_id, 'etapa_id', r.id, 'ordem', r.ordem,
      'rodada', r.rodada, 'decisao', 'prazo_vencido', 'papel', 'sistema',
      'decidido_em', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
    ));

    if r.acao_ao_expirar = 'remind' then
      update public.autorizacao_etapas set lembrete_enviado_em = now() where id = r.id;
      perform auditoria.registrar_evento_do_sistema(
        r.ws, r.fluxo_codigo, 'autorizacao_etapas', r.id,
        'autorizacao.lembrete_enviado', r.rodada::integer, null,
        jsonb_build_object('ordem', r.ordem, 'estado', 'open')
      );

    elsif r.acao_ao_expirar = 'escalate' then
      insert into public.autorizacao_decisoes (
        workspace_id, autorizacao_id, etapa_id, ator_id, papel_exercido,
        decisao, hash_decisao
      ) values (r.ws, r.autorizacao_id, r.id, null, 'sistema', 'escalated', v_hash_dec);

      select * into v_proxima from public.autorizacao_etapas e
       where e.autorizacao_id = r.autorizacao_id and e.ordem > r.ordem and e.estado = 'waiting'
       order by e.ordem limit 1;

      if v_proxima.id is not null then
        update public.autorizacao_etapas
           set estado = 'escalated', escalada_em = now(), fechada_em = now()
         where id = r.id;

        update public.autorizacao_etapas e
           set estado = 'open', aberta_em = now(),
               prazo_em = public.somar_dias_uteis(now(), e.prazo_dias_uteis)
         where e.id = v_proxima.id;
        update public.autorizacoes a
           set estado = case when a.tipo = 'document' then 'in_validation' else 'pending' end,
               etapa_atual = v_proxima.ordem,
               prazo_em = (select e2.prazo_em from public.autorizacao_etapas e2 where e2.id = v_proxima.id)
         where a.id = r.autorizacao_id;
        perform auditoria.registrar_evento_do_sistema(
          r.ws, r.fluxo_codigo, 'autorizacao_etapas', v_proxima.id,
          'autorizacao.etapa_aberta', r.rodada::integer, null,
          jsonb_build_object('estado', 'open', 'ordem', v_proxima.ordem)
        );
      else
        -- Ultima etapa, que e a homologacao da Diretoria: nao ha para onde
        -- escalar. Fechar aqui deixava o pedido em in_validation apontando para
        -- etapa fechada, sem decisao possivel e fora do proprio job. A etapa
        -- continua open, com prazo renovado de dois dias uteis e alcance
        -- ampliado a quem exerce autorizacao.homologar, com quorum 1.
        v_prazo_novo := public.somar_dias_uteis(now(), 2);

        -- Alcance: o papel da propria etapa quando ele ja exerce
        -- autorizacao.homologar; se nao exercer, o papel de homologacao com
        -- mais gente vigente, para que a etapa nao fique sem executor.
        select case
                 when exists (select 1 from public.papel_permissoes pp
                               where pp.papel = r.papel_aprovador
                                 and pp.permissao = 'autorizacao.homologar'::public.permissao)
                 then r.papel_aprovador
                 else (select pp.papel
                         from public.papel_permissoes pp
                         left join public.usuario_papeis up
                                on up.papel = pp.papel
                               and up.inicio <= now()
                               and (up.fim is null or up.fim > now())
                        where pp.permissao = 'autorizacao.homologar'::public.permissao
                        group by pp.papel
                        order by count(up.user_id) desc, pp.papel
                        limit 1)
               end
          into v_papel_homologa;

        update public.autorizacao_etapas e
           set escalada_em = now(),
               prazo_em = v_prazo_novo,
               lembrete_enviado_em = now(),
               papel_aprovador = coalesce(v_papel_homologa, e.papel_aprovador),
               quorum = 1
         where e.id = r.id;

        update public.autorizacoes a
           set prazo_em = v_prazo_novo
         where a.id = r.autorizacao_id;

        -- Notificacao autorizacao.prazo_vencendo a quem homologa e ao
        -- administrador. O job roda por service_role, sem sessao: escreve
        -- direto no sino e na fila, e nao por public.registrar_notificacoes,
        -- que exige auth.uid().
        with alvos as (
          select distinct up.user_id
            from public.usuario_papeis up
            join public.profiles pf on pf.id = up.user_id
           where (
                   exists (select 1 from public.papel_permissoes pp
                            where pp.papel = up.papel
                              and pp.permissao = 'autorizacao.homologar'::public.permissao)
                   or up.papel = 'administrador'
                 )
             and up.inicio <= now()
             and (up.fim is null or up.fim > now())
             and pf.desativado_em is null
             and pf.eliminado_em is null
        ),
        novas as (
          insert into public.notifications (
            workspace_id, user_id, title, message, link, tipo, entidade_tipo, entidade_id
          )
          select r.ws, a.user_id, 'autorizacao.prazo_vencendo', null, null,
                 'autorizacao.prazo_vencendo', 'autorizacoes', r.autorizacao_id
            from alvos a
          returning id, workspace_id, user_id
        )
        insert into operacao.fila_emails (
          workspace_id, destinatario_id, notificacao_id, tipo,
          entidade_tipo, entidade_id, prioridade, status
        )
        select n.workspace_id, n.user_id, n.id, 'autorizacao.prazo_vencendo',
               'autorizacoes', r.autorizacao_id, 'imediato', 'queued'
          from novas n;
      end if;

      perform auditoria.registrar_evento_do_sistema(
        r.ws, r.fluxo_codigo, 'autorizacao_etapas', r.id,
        'autorizacao.escalada', r.rodada::integer,
        jsonb_build_object('estado', 'open', 'ordem', r.ordem),
        case when v_proxima.id is not null
             then jsonb_build_object('estado', 'escalated', 'ordem', r.ordem)
             else jsonb_build_object('estado', 'open', 'ordem', r.ordem, 'quorum', 1,
                                     'prazo_em', to_char(v_prazo_novo at time zone 'UTC',
                                                         'YYYY-MM-DD"T"HH24:MI:SSOF'))
        end,
        r.hash_arquivo_submissao, v_hash_dec
      );

    elsif r.acao_ao_expirar = 'auto_approve' and r.tipo_pedido = 'light' then
      insert into public.autorizacao_decisoes (
        workspace_id, autorizacao_id, etapa_id, ator_id, papel_exercido, decisao, hash_decisao
      ) values (r.ws, r.autorizacao_id, r.id, null, 'sistema', 'auto_approved', v_hash_dec);
      update public.autorizacao_etapas
         set estado = 'approved', fechada_em = now() where id = r.id;
      update public.autorizacoes a
         set estado = 'auto_approved', automatica = true, etapa_atual = null,
             prazo_em = null, concluida_em = now()
       where a.id = r.autorizacao_id;
      perform auditoria.registrar_evento_do_sistema(
        r.ws, r.fluxo_codigo, 'autorizacoes', r.autorizacao_id,
        'autorizacao.aprovada_automaticamente', r.rodada::integer,
        jsonb_build_object('estado', 'pending'),
        jsonb_build_object('estado', 'auto_approved', 'automatica', true),
        r.hash_arquivo_submissao, v_hash_dec
      );

    elsif r.acao_ao_expirar = 'auto_deny' and r.tipo_pedido = 'light' then
      -- denied so quando a propria regra manda negar por decurso; nos demais
      -- casos o pedido apenas expira, e e por aqui que o valor expired do check
      -- de public.autorizacoes ganha caminho de entrada.
      v_estado_venc := case when r.tipo_gestao_padrao = 'auto_deny' then 'denied' else 'expired' end;
      insert into public.autorizacao_decisoes (
        workspace_id, autorizacao_id, etapa_id, ator_id, papel_exercido,
        decisao, motivo, hash_decisao
      ) values (r.ws, r.autorizacao_id, r.id, null, 'sistema', 'auto_denied',
                'Prazo vencido sem decisao.', v_hash_dec);
      update public.autorizacao_etapas set estado = 'expired', fechada_em = now() where id = r.id;
      update public.autorizacoes a
         set estado = v_estado_venc, automatica = true, etapa_atual = null, prazo_em = null,
             motivo_negacao = case when v_estado_venc = 'denied'
                                   then 'Prazo vencido sem decisao.' else null end,
             concluida_em = now()
       where a.id = r.autorizacao_id;
      perform auditoria.registrar_evento_do_sistema(
        r.ws, r.fluxo_codigo, 'autorizacoes', r.autorizacao_id,
        case when v_estado_venc = 'denied' then 'autorizacao.negada' else 'autorizacao.expirada' end,
        r.rodada::integer,
        jsonb_build_object('estado', 'pending'),
        jsonb_build_object('estado', v_estado_venc, 'automatica', true),
        r.hash_arquivo_submissao, v_hash_dec
      );

    else
      -- Documento nunca e aprovado por decurso de prazo: so escala.
      update public.autorizacao_etapas set lembrete_enviado_em = now() where id = r.id;
    end if;

    v_mexidas := v_mexidas + 1;
  end loop;

  -- Arquivamento automatico do que passou de arquivar_em.
  for r in
    select a.*, reg.fluxo_codigo
      from public.autorizacoes a
      join public.autorizacao_regras reg on reg.id = a.regra_id
     where a.arquivar_em is not null and a.arquivar_em <= now()
       and a.tipo = 'document' and a.estado = 'published'
  loop
    update public.autorizacoes set estado = 'archived' where id = r.id;
    perform auditoria.registrar_evento_do_sistema(
      r.workspace_id, r.fluxo_codigo, 'autorizacoes', r.id,
      'documento.arquivado', r.rodada::integer,
      jsonb_build_object('estado', 'published'),
      jsonb_build_object('estado', 'archived')
    );
    v_mexidas := v_mexidas + 1;
  end loop;

  return v_mexidas;
end;
$$;

comment on function public.processar_prazos_autorizacao() is 'Job leve de prazo, lembrete, escalonamento e decisao por decurso, transposto de WorkflowStateEscalation do Mayan (state, transition, unit, amount). So muda estados e insere eventos; o e-mail sai por rota da intranet chamada pelo cron da Vercel, para nao criar no banco uma dependencia que a Redacao nao tem. Na ultima etapa nao ha para onde escalar: a etapa segue open, com prazo renovado de dois dias uteis, alcance ampliado a quem exerce autorizacao.homologar e quorum 1, porque pedido em in_review ou in_validation sem etapa open e defeito, nao estado. Documento nunca e aprovado por decurso de prazo; o tramite leve com acao_ao_expirar auto_deny termina em denied so quando a regra manda negar, e em expired nos demais casos.';

revoke all on function public.processar_prazos_autorizacao() from public, anon, authenticated;
grant execute on function public.processar_prazos_autorizacao() to service_role;

do $$
begin
  -- pg_cron a confirmar nas extensoes do projeto (premissa declarada em docs/03,
  -- secao 5.6). Sem a extensao, a rota de cron da Vercel chama a mesma funcao.
  perform 1 from pg_catalog.pg_extension where extname = 'pg_cron';
  if found then
    perform cron.schedule('autorizacao_prazos', '0 * * * *',
                          'select public.processar_prazos_autorizacao();');
    perform cron.schedule('auditoria_verificar', '15 6 * * *',
                          'select * from auditoria.verificar_cadeia(null, ''pg_cron'');');
  else
    raise notice 'pg_cron ausente: agende processar_prazos_autorizacao e verificar_cadeia pela rota de cron da Vercel.';
  end if;
exception when others then
  raise notice 'Agendamento de pg_cron nao aplicado: %', sqlerrm;
end $$;

-- ============================================================================
-- 15. Ponte do activity_log da Redacao para a cadeia
-- ============================================================================

create or replace function auditoria.ponte_activity_log()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_acao text;
begin
  -- Traducao conservadora: so o que cabe no catalogo entra na cadeia. O metadata
  -- da Redacao nao e copiado, porque pode conter texto com dado pessoal.
  v_acao := case
    when new.action in ('published','site_published','social_published') then 'documento.publicado'
    when new.action in ('approved','approval_approved')                  then 'autorizacao.aprovada'
    when new.action in ('rejected','changes_requested')                  then 'autorizacao.devolvida'
    when new.action in ('archived')                                      then 'documento.arquivado'
    when new.action in ('version_created','created')                     then 'documento.versao_criada'
    else null
  end;

  if v_acao is null or new.entity_id is null or new.workspace_id is null then
    return new;
  end if;

  insert into auditoria.eventos (
    workspace_id, fluxo, entidade_tipo, entidade_id, ator_id, papel, acao,
    depois, hash_anterior, hash_linha
  ) values (
    new.workspace_id, 'F09', coalesce(new.entity_type, 'activity_log'), new.entity_id,
    new.actor_id, 'editorial', v_acao,
    jsonb_build_object('estado', new.action),
    repeat('0', 64), repeat('0', 64)
  );

  return new;

exception when others then
  -- Erro na trilha nunca impede a Redacao de trabalhar: este trigger e AFTER
  -- INSERT em public.activity_log, escrito por praticamente toda Server Action
  -- em producao, e qualquer falha aqui (contencao no advisory lock, catalogo de
  -- fluxos nao semeado, action traduzida para fora do check de acao) abortaria a
  -- transacao da Redacao. A falha fica visivel na tela de operacao pela metrica
  -- ponte_auditoria_falhou.
  begin
    insert into operacao.uso_plano (workspace_id, dia, metrica, valor, origem, observacao)
    values (new.workspace_id, current_date, 'ponte_auditoria_falhou', 1, 'automatico',
            'Ponte do activity_log recusada; a escrita da Redacao seguiu.')
    on conflict (workspace_id, dia, metrica) do update
      set valor = operacao.uso_plano.valor + 1, registrado_em = now();
  exception when others then
    null;
  end;
  return new;
end;
$$;

comment on function auditoria.ponte_activity_log() is 'Trigger AFTER INSERT que leva a trilha editorial existente para a cadeia com codigo de fluxo neutro F09, sem alterar as Server Actions da Redacao. Sai em migracao marcada -- limpeza: quando as actions passarem a chamar registrarEvento() direto. Nao copia metadata: o campo e livre e pode conter dado pessoal. O corpo inteiro fica em bloco de excecao que devolve a linha sem erro, pela mesma razao que ja vale para o hook de token: erro na trilha nunca impede a Redacao de trabalhar, e a falha fica visivel na tela de operacao pela metrica ponte_auditoria_falhou de operacao.uso_plano.';

drop trigger if exists activity_log_ponte_auditoria on public.activity_log;
create trigger activity_log_ponte_auditoria
  after insert on public.activity_log
  for each row execute function auditoria.ponte_activity_log();

-- ============================================================================
-- 16. Leitura publica de retorno fixo
-- ============================================================================

create or replace function public.verificar_codigo(p_codigo text)
returns table (
  encontrado           boolean,
  hash_arquivo         text,
  hash_decisao         text,
  decidido_em          timestamptz,
  estado_publico       text,
  cadeia_ok            boolean,
  cadeia_verificada_em timestamptz,
  ancora_dia           date,
  ancora_hash          text,
  ots_completa         boolean,
  bloco_bitcoin        integer
)
language plpgsql security definer set search_path = '' as $$
declare
  v_a  public.autorizacoes%rowtype;
  v_s  public.assinaturas%rowtype;
  v_ws uuid;
begin
  encontrado := false;
  -- Nunca nulo: o conjunto de campos devolvido e o mesmo para qualquer codigo,
  -- por construcao. Estado so distingue vigente de revogada no fluxo de imagem.
  estado_publico := 'nao_aplicavel';

  select * into v_a from public.autorizacoes a where a.codigo_verificacao = upper(btrim(p_codigo));
  if found then
    encontrado   := true;
    v_ws         := v_a.workspace_id;
    hash_arquivo := v_a.hash_arquivo_submissao;
    decidido_em  := v_a.concluida_em;
    -- Estado so no fluxo de imagem, para que veiculo e parceiro saibam se ainda
    -- podem usar; decisao pendente da Diretoria, opcao recomendada aplicada.
    -- Fora dele o valor e nao_aplicavel, e nunca nulo: presenca de valor nao
    -- pode identificar o fluxo do documento consultado.
    estado_publico := case
      when v_a.tipo_ato in ('uso_imagem','autorizacao_imagem')
        then case when v_a.estado in ('approved','auto_approved','published') then 'vigente' else 'revogada' end
      else 'nao_aplicavel'
    end;
    select d.hash_decisao into hash_decisao
      from public.autorizacao_decisoes d
     where d.autorizacao_id = v_a.id
     order by d.decidido_em desc limit 1;
    update public.autorizacoes set consultas_publicas = consultas_publicas + 1 where id = v_a.id;
  else
    select * into v_s from public.assinaturas s where s.codigo_verificacao = upper(btrim(p_codigo));
    if found then
      encontrado   := true;
      v_ws         := v_s.workspace_id;
      hash_arquivo := coalesce(v_s.hash_pdf_assinado, v_s.hash_pdf_gerado, v_s.hash_arquivo);
      decidido_em  := v_s.assinado_em;
      estado_publico := 'nao_aplicavel';
      select d.hash_decisao into hash_decisao
        from public.autorizacao_decisoes d
       where d.autorizacao_id = v_s.autorizacao_id
       order by d.decidido_em desc limit 1;
    end if;
  end if;

  if not encontrado then
    return next;
    return;
  end if;

  select v.ok, v.executado_em into cadeia_ok, cadeia_verificada_em
    from auditoria.verificacoes v
   where v.workspace_id is not distinct from v_ws
   order by v.executado_em desc limit 1;

  select an.dia, an.hash_agregado, an.ots_completa, an.bloco_bitcoin
    into ancora_dia, ancora_hash, ots_completa, bloco_bitcoin
    from auditoria.ancoras an
   where an.workspace_id = v_ws and an.publicado_em is not null
   order by an.dia desc limit 1;

  return next;
end;
$$;

comment on function public.verificar_codigo(text) is 'Retorno fixo da pagina publica /verificar/[codigo]: hash do arquivo, hash da decisao, data, resultado da ultima verificacao da cadeia e a ancora do dia. Nao devolve fluxo, papel, setor, nome, posicao na cadeia nem conteudo, porque em equipe pequena esses quase-identificadores identificam a pessoa (docs/04, secoes 6 e 7, e LGPD art. 6, III). O conjunto de campos devolvido e o mesmo para qualquer codigo, por construcao: estado_publico vem sempre preenchido, com nao_aplicavel fora do fluxo de imagem e vigente ou revogada apenas quando o tipo de ato e uso_imagem ou autorizacao_imagem, para que a simples presenca do valor nao identifique o fluxo consultado. Molde do /validar/[token] do Curso; o limite de taxa e o noindex ficam no proxy.ts.';

create or replace function auditoria.listar_ancoras(p_workspace_id uuid, p_limite integer default 90)
returns table (dia date, hash_agregado text, ots_completa boolean, bloco_bitcoin integer)
language sql security definer set search_path = '' stable as $$
  select a.dia, a.hash_agregado, a.ots_completa, a.bloco_bitcoin
    from auditoria.ancoras a
   where a.workspace_id = p_workspace_id and a.publicado_em is not null
   order by a.dia desc
   limit least(greatest(coalesce(p_limite, 90), 1), 365);
$$;

comment on function auditoria.listar_ancoras(uuid, integer) is 'Lista publica de /verificar/ancoras: apenas dia e hash agregado, sem rotulo de fluxo e sem contagem, para nao revelar o ritmo interno de aprovacoes. Substitui a antiga ideia de transparencia por fluxo (docs/04, secao 6).';

-- anon nao recebe privilegio em lugar nenhum: as duas rotas publicas sao
-- renderizadas no servidor com a chave de servico, como faz /validar/[token] do
-- Curso. O retorno fixo e que garante que a pagina nao vaze mais do que o contrato.
revoke all on function public.verificar_codigo(text)            from public, anon, authenticated;
revoke all on function auditoria.listar_ancoras(uuid, integer)  from public, anon, authenticated;
grant execute on function public.verificar_codigo(text)           to service_role;
grant execute on function auditoria.listar_ancoras(uuid, integer) to service_role;

create or replace function public.consultar_trilha_do_documento(p_documento_id uuid)
returns table (
  ocorrido_em  timestamptz,
  acao         text,
  papel        text,
  hash_arquivo text,
  hash_decisao text
)
language plpgsql security definer set search_path = '' stable as $$
declare
  v_pasta uuid;
begin
  select d.pasta_id into v_pasta from public.documentos d where d.id = p_documento_id;
  if v_pasta is null then
    raise exception 'Documento nao encontrado.' using errcode = 'P0002';
  end if;

  -- coalesce porque private.papel_na_pasta devolve nulo para quem nao alcanca a
  -- pasta, e nulo em condicao de recusa deixaria a porta aberta.
  if not coalesce(
    coalesce((select private.papel_na_pasta(v_pasta)), '') in ('revisor','editor')
    or (select public.autorizar('trilha.ler_completa'::public.permissao, null))
    or (select public.autorizar('operacao.administrar'::public.permissao, null))
  , false) then
    raise exception 'A trilha do documento e de quem revisa ou edita a pasta, do auditor e do administrador.'
      using errcode = '42501';
  end if;

  return query
  with alvos as (
    select 'documentos'::text as tipo, p_documento_id as id
    union all
    select 'documento_versoes', dv.id
      from public.documento_versoes dv
     where dv.documento_id = p_documento_id
    union all
    select 'autorizacoes', a.id
      from public.autorizacoes a
     where (a.objeto_tipo = 'documentos' and a.objeto_id = p_documento_id)
        or exists (select 1 from public.documento_versoes dv
                    where dv.id = a.versao_id and dv.documento_id = p_documento_id)
    union all
    select 'autorizacao_etapas', e.id
      from public.autorizacao_etapas e
      join public.autorizacoes a on a.id = e.autorizacao_id
     where (a.objeto_tipo = 'documentos' and a.objeto_id = p_documento_id)
        or exists (select 1 from public.documento_versoes dv
                    where dv.id = a.versao_id and dv.documento_id = p_documento_id)
    union all
    select 'assinaturas', s.id
      from public.assinaturas s
     where s.documento_id = p_documento_id
  )
  select ev.ocorrido_em, ev.acao, ev.papel, ev.hash_arquivo, ev.hash_decisao
    from auditoria.eventos ev
    join alvos t on t.tipo = ev.entidade_tipo and t.id = ev.entidade_id
   order by ev.ocorrido_em, ev.seq;
end;
$$;

comment on function public.consultar_trilha_do_documento(uuid) is 'Aba Trilha da ficha do documento, de retorno fixo: data, acao, papel, hash do arquivo e hash da decisao, sem hash_anterior, hash_linha, ip_hash, user_agent_hash, antes e depois. Existe porque a aba e prometida ao papel local revisor, que nao e papel institucional, enquanto a unica policy de leitura de auditoria.eventos exige trilha.ler_completa, concedida so a auditor e administrador: sem ela o coordenador abre a aba e recebe lista vazia. Libera revisor e editor da pasta do documento, alem de quem tem trilha.ler_completa ou operacao.administrar; a leitura direta de auditoria.eventos continua restrita como esta.';

revoke all on function public.consultar_trilha_do_documento(uuid) from public, anon;
grant execute on function public.consultar_trilha_do_documento(uuid) to authenticated;

-- ============================================================================
-- 17. lgpd.operacoes, lgpd.pedidos_titular, lgpd.incidentes
-- ============================================================================

create table if not exists lgpd.operacoes (
  fluxo_codigo         text primary key references auditoria.fluxos (codigo),
  finalidade           text not null,
  base_legal           text not null,
  dados_categorias     text[] not null default '{}',
  dados_sensiveis      boolean not null default false,
  titulares_categorias text[] not null default '{}',
  compartilhamento     text,
  retencao             text,
  medidas_seguranca    text not null,
  colunas              text[] not null default '{}',
  publico              boolean not null default true,
  atualizado_em        timestamptz not null default now(),
  atualizado_por       uuid references public.profiles (id) on delete set null
);

comment on table lgpd.operacoes is 'Registro simplificado de operacoes de tratamento (LGPD art. 37, modelo da Resolucao CD/ANPD 2/2022), uma linha por fluxo, chaveada pelo mesmo codigo neutro de auditoria.fluxos. Fonte unica de finalidade, base legal e retencao dos fluxos que nao sao documento; alimenta a pagina /privacidade. Sem workspace_id: o registro e do controlador. O fluxo de certificados do Curso continua no projeto proprio e fica fora do registro da intranet nesta rodada.';
comment on column lgpd.operacoes.retencao is 'Prazo e regra de eliminacao. Fica em branco enquanto a Diretoria, com o encarregado e a assessoria juridica, nao fixar: docs/04, secao 5, so propoe.';
comment on column lgpd.operacoes.colunas is 'Tabelas e colunas cobertas, no formato schema.tabela.coluna, conferidas por teste pgTAP contra as colunas marcadas nos comment on column no formato ''dado_pessoal | descricao'' e ''dado_sensivel | descricao''. O teste de conformidade compara o prefixo antes da barra com esta lista, e linha com colunas vazia reprova.';

insert into lgpd.operacoes (fluxo_codigo, finalidade, base_legal, dados_categorias, dados_sensiveis, titulares_categorias, compartilhamento, retencao, medidas_seguranca, colunas, publico) values
  ('F01', 'Tramitar e homologar documentos institucionais.',
   'LGPD art. 37 e art. 6, X, para a trilha; art. 7, II, quando ha obrigacao legal sobre o documento; art. 7, IX, com ponderacao registrada nos demais.',
   array['identificador interno','papel','setor','hash de arquivo','hash de decisao'], false,
   array['colaborador','voluntario','diretoria'], 'Supabase (banco), Vercel (aplicacao).',
   null, 'RLS em todas as tabelas, MFA TOTP para quem decide, trilha append-only com hash encadeado, backup proprio fora do provedor.',
   array['public.autorizacoes.dados','public.autorizacao_decisoes.motivo','public.autorizacao_decisoes.ip','public.autorizacao_decisoes.user_agent'], true),
  ('F02', 'Decidir pedidos leves (uso de imagem, participacao em acao, ressarcimento, acesso a pasta).',
   'LGPD art. 7, I, para uso de imagem; art. 7, V, para ressarcimento e participacao; art. 37 para a trilha.',
   array['identificador interno','papel','setor','dados do formulario do pedido'], false,
   array['colaborador','voluntario'], 'Supabase, Vercel.',
   null, 'RLS, MFA para quem decide, trilha append-only.',
   array['public.autorizacoes.dados','public.autorizacao_decisoes.motivo','public.autorizacao_decisoes.ip','public.autorizacao_decisoes.user_agent'], true),
  ('F03', 'Registrar assinatura eletronica e sua evidencia.',
   'Lei 14.063/2020, art. 4, e MP 2.200-2, art. 10, parag. 2; LGPD art. 37 e art. 6, X, para a trilha.',
   array['identificador interno','endereco IP','agente do navegador','hash do PDF'], false,
   array['colaborador','voluntario','parceiro externo'], 'Assinador gov.br e validador do ITI, por acao do proprio signatario.',
   null, 'IP e agente so em tabela apagavel; na cadeia entra apenas o hash truncado.',
   array['public.assinaturas.ip','public.assinaturas.user_agent','public.assinaturas.certificado_emissor'], true),
  ('F06', 'Provar autorizacao de uso de imagem e sua revogacao.',
   'LGPD art. 7, I, e art. 18, VI; Codigo Civil art. 20; art. 37 para a trilha.',
   array['identificador interno','hash do termo','hash do arquivo'], false,
   array['voluntario','beneficiario','parceiro externo'], 'Redacao (publicacao), redes sociais quando autorizado.',
   'Enquanto a autorizacao vigorar mais o prazo indicado pela assessoria juridica; a revogacao e evento posterior, nunca apagamento.',
   'Foto e video so no armazenamento restrito; nenhum rotulo que ligue hash a pessoa entra na cadeia ou na pagina publica.',
   array['public.autorizacoes.dados','public.consentimentos.evidencia'], true),
  ('F08', 'Guardar dados de saude de voluntario indispensaveis a atuacao.',
   'LGPD art. 11: consentimento especifico e destacado ou obrigacao legal. Legitimo interesse nao se aplica.',
   array['tipo sanguineo','restricoes de saude'], true,
   array['voluntario'], 'Nenhum.',
   null, 'Tabela separada com RLS propria, setor Saude restrito por padrao, nada deste fluxo aparece em pagina publica.',
   array['public.profiles_restritos.tipo_sanguineo','public.profiles_restritos.restricoes_saude'], false),
  ('F10', 'Atender pedidos do titular e registrar exportacao e anonimizacao.',
   'LGPD art. 18 e art. 19, II; art. 37 para a trilha.',
   array['identificador interno','hash do contato'], false,
   array['colaborador','voluntario','parceiro externo','beneficiario'], 'Nenhum.',
   'Pedido guardado enquanto durar a comprovacao do atendimento; descricao anonimizada apos o prazo fixado pela Diretoria.',
   'Canal sem login com codigo de alta entropia e limite de taxa; contato guardado so como hash.',
   array['lgpd.pedidos_titular.contato_hash','lgpd.pedidos_titular.descricao','lgpd.pedidos_titular.resposta_resumo'], true),
  ('F04', 'Guardar, versionar e publicar documentos institucionais na biblioteca.',
   'LGPD art. 7, II, quando ha obrigacao legal de guarda; art. 7, IX, com ponderacao registrada, no acervo interno; art. 37 para a trilha.',
   array['identificador interno','titulo e metadados do documento','texto extraido do arquivo','hash de arquivo'], false,
   array['colaborador','voluntario','beneficiario'], 'Supabase (banco), Vercel (aplicacao e armazenamento do arquivo).',
   null, 'RLS por pasta com papel local, nivel sigiloso com credencial nominal e aal2, hash SHA-256 por versao e reconferencia periodica.',
   array['public.documentos.titulo','public.documentos.descricao','public.documentos.metadados','public.documento_versoes.texto_extraido','public.documento_versoes.motivo'], true),
  ('F05', 'Publicar aviso, aprovar conteudo e registrar confirmacao de leitura no mural.',
   'LGPD art. 7, II, quando o aviso cumpre obrigacao legal; art. 7, IX, nos demais; art. 37 para a trilha.',
   array['identificador interno','setor','texto do aviso e do comentario','data de leitura'], false,
   array['colaborador','voluntario'], 'Supabase, Vercel.',
   null, 'RLS por grupo, moderacao com trilha, relatorio de leitura agregado por padrao.',
   array['public.avisos.corpo','public.comentarios.corpo','public.comentarios.motivo','public.aviso_leituras.user_id'], true),
  ('F07', 'Cadastrar identidade, vinculo, papel, delegacao, convite e consentimento.',
   'Lei 9.608 e MROSC para o termo de adesao e a prestacao de contas (LGPD art. 7, II); art. 7, I, para o consentimento; art. 37 para a trilha.',
   array['nome','nome social','CPF','documento de identidade','data de nascimento','endereco','telefone','e-mail','habilitacao','credencial'], false,
   array['colaborador','voluntario','parceiro externo'], 'Supabase, Vercel.',
   null, 'profiles_restritos com RLS propria e leitura so com pessoa.ver_restrito, MFA para conceder papel, trilha append-only.',
   array['public.profiles.nome_social','public.profiles.email_contato','public.profiles.telefone','public.profiles.apresentacao','public.profiles_restritos.cpf','public.profiles_restritos.rg','public.profiles_restritos.data_nascimento','public.profiles_restritos.endereco','public.profiles_restritos.habilitacao','public.convites.email','public.consentimentos.evidencia','public.credenciais.numero'], true),
  ('F09', 'Levar a trilha editorial ja existente na Redacao para a cadeia de auditoria.',
   'LGPD art. 37 e art. 6, X.',
   array['identificador interno','acao editorial'], false,
   array['colaborador'], 'Supabase, Vercel.',
   null, 'A ponte nao copia metadata da Redacao, engole a propria falha para nunca derrubar a escrita editorial e deixa a falha visivel em operacao.uso_plano.',
   array['public.activity_log.actor_id','public.activity_log.metadata'], true),
  ('F11', 'Exibir o diretorio interno de pessoas e o contato de trabalho.',
   'LGPD art. 7, IX, com ponderacao registrada, e art. 7, I, para telefone e e-mail exibidos mediante consentimento.',
   array['nome social','e-mail de contato','telefone','apresentacao','setor'], false,
   array['colaborador','voluntario'], 'Nenhum.',
   null, 'Visibilidade por coluna (email_visivel, telefone_visivel), consentimento vigente de finalidade telefone_no_diretorio e nada do diretorio em pagina publica.',
   array['public.profiles.nome_social','public.profiles.email_contato','public.profiles.telefone','public.profiles.apresentacao'], true),
  ('F12', 'Exportar o relatorio nominal de leitura de aviso obrigatorio, com finalidade escrita.',
   'LGPD art. 7, II, quando ha obrigacao legal, e art. 7, IX, com ponderacao registrada; art. 37 para a trilha.',
   array['identificador interno','setor','data de confirmacao de leitura'], false,
   array['colaborador','voluntario'], 'Nenhum.',
   null, 'O relatorio padrao e agregado; a exportacao nominal exige pessoa.ver_restrito, motivo de obrigatoriedade escrito e fica registrada na trilha.',
   array['public.aviso_leituras.user_id','public.aviso_leituras.confirmado_em','public.profiles.nome_social'], true)
on conflict (fluxo_codigo) do nothing;

alter table lgpd.operacoes enable row level security;

create policy operacoes_select_encarregado on lgpd.operacoes for select to authenticated
  using (
    (select public.autorizar('trilha.ler_completa'::public.permissao, null))
    or (select public.autorizar('lgpd.responder_titular'::public.permissao, null))
  );

create policy operacoes_insert_encarregado on lgpd.operacoes for insert to authenticated
  with check (
    (select public.autorizar('lgpd.responder_titular'::public.permissao, null))
    and (select private.exige_aal2())
    and atualizado_por = (select auth.uid())
  );

create policy operacoes_update_encarregado on lgpd.operacoes for update to authenticated
  using ((select public.autorizar('lgpd.responder_titular'::public.permissao, null)))
  with check (
    (select public.autorizar('lgpd.responder_titular'::public.permissao, null))
    and (select private.exige_aal2())
  );

revoke all on table lgpd.operacoes from public, anon;
grant select, insert, update on table lgpd.operacoes to authenticated;

drop trigger if exists operacoes_toca_atualizado_em on lgpd.operacoes;
create trigger operacoes_toca_atualizado_em
  before update on lgpd.operacoes
  for each row execute function public.tocar_atualizado_em();

create table if not exists lgpd.pedidos_titular (
  id             uuid primary key default gen_random_uuid(),
  workspace_id   uuid not null references public.workspaces (id) on delete cascade,
  codigo_publico text not null unique default public.gerar_codigo_verificacao()
                   check (codigo_publico ~ '^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$'),
  tipo           text not null check (tipo in ('access','correction','deletion','portability','revocation')),
  titular_id     uuid references public.profiles (id) on delete set null,
  contato_hash   text not null check (contato_hash ~ '^[0-9a-f]{64}$'),
  descricao      text,
  status         text not null default 'received'
                   check (status in ('received','identifying','in_progress','answered','refused')),
  recebido_em    timestamptz not null default now(),
  prazo_em       timestamptz not null default (now() + interval '15 days'),
  respondido_em  timestamptz,
  resposta_resumo text,
  hipotese_recusa text,
  responsavel_id uuid references public.profiles (id) on delete set null,
  criado_em      timestamptz not null default now(),
  constraint pedidos_titular_recusa_com_hipotese check (
    status <> 'refused' or coalesce(btrim(hipotese_recusa), '') <> ''
  )
);

comment on table lgpd.pedidos_titular is 'Pedidos do canal do titular (LGPD art. 18) com codigo publico de acompanhamento sem login, hash do e-mail informado, prazo de 15 dias do art. 19, II, e hipotese de recusa do art. 16. Fila com trilha em vez de caixa de e-mail, no molde dos portais de titular da Cruz Vermelha Canadense citados na recomendacao.';
comment on column lgpd.pedidos_titular.contato_hash is 'SHA-256 do e-mail informado: a lista localiza o pedido sem guardar o endereco em claro.';

create index if not exists pedidos_titular_status_prazo_em_idx on lgpd.pedidos_titular (status, prazo_em);
create index if not exists pedidos_titular_titular_id_idx      on lgpd.pedidos_titular (titular_id);

alter table lgpd.pedidos_titular enable row level security;

create policy pedidos_titular_select_encarregado on lgpd.pedidos_titular for select to authenticated
  using (
    titular_id = (select auth.uid())
    or (select public.autorizar('lgpd.responder_titular'::public.permissao, null))
    or (select public.autorizar('trilha.ler_completa'::public.permissao, null))
  );

create policy pedidos_titular_update_encarregado on lgpd.pedidos_titular for update to authenticated
  using ((select public.autorizar('lgpd.responder_titular'::public.permissao, null)))
  with check (
    (select public.autorizar('lgpd.responder_titular'::public.permissao, null))
    and (select private.exige_aal2())
  );

revoke all on table lgpd.pedidos_titular from public, anon;
grant select, update on table lgpd.pedidos_titular to authenticated;

create or replace function lgpd.abrir_pedido_titular(
  p_workspace_id uuid,
  p_tipo         text,
  p_contato      text,
  p_descricao    text default null
) returns text
language plpgsql security definer set search_path = '' as $$
declare v_codigo text;
begin
  if p_tipo not in ('access','correction','deletion','portability','revocation') then
    raise exception 'Tipo de pedido invalido.' using errcode = '22023';
  end if;
  if coalesce(btrim(p_contato), '') = '' then
    raise exception 'Informe um contato para a resposta.' using errcode = '22023';
  end if;

  insert into lgpd.pedidos_titular (workspace_id, tipo, contato_hash, descricao)
  values (p_workspace_id, p_tipo,
          encode(sha256(convert_to(lower(btrim(p_contato)), 'UTF8')), 'hex'),
          left(coalesce(p_descricao, ''), 2000))
  returning codigo_publico into v_codigo;

  return v_codigo;
end;
$$;

create or replace function lgpd.consultar_pedido_titular(p_codigo text)
returns table (encontrado boolean, tipo text, status text, recebido_em timestamptz,
               prazo_em timestamptz, respondido_em timestamptz)
language plpgsql security definer set search_path = '' as $$
begin
  encontrado := false;
  select true, p.tipo, p.status, p.recebido_em, p.prazo_em, p.respondido_em
    into encontrado, tipo, status, recebido_em, prazo_em, respondido_em
    from lgpd.pedidos_titular p
   where p.codigo_publico = upper(btrim(p_codigo));
  encontrado := coalesce(encontrado, false);
  return next;
end;
$$;

comment on function lgpd.abrir_pedido_titular(uuid, text, text, text) is 'Entrada do formulario /privacidade/pedido, sem login. O contato entra so como hash; o limite de taxa (5 por dia por IP) fica na rota, com operacao.permitir.';
comment on function lgpd.consultar_pedido_titular(text) is 'Retorno fixo do acompanhamento sem login: tipo, estado e datas. Nunca devolve descricao, contato, responsavel nem resposta.';

revoke all on function lgpd.abrir_pedido_titular(uuid, text, text, text) from public, anon, authenticated;
revoke all on function lgpd.consultar_pedido_titular(text)               from public, anon, authenticated;
grant execute on function lgpd.abrir_pedido_titular(uuid, text, text, text) to service_role;
grant execute on function lgpd.consultar_pedido_titular(text)               to service_role;

create table if not exists lgpd.incidentes (
  id                       uuid primary key default gen_random_uuid(),
  workspace_id             uuid not null references public.workspaces (id) on delete cascade,
  detectado_em             timestamptz not null,
  descricao                text not null,
  dados_categorias         text[] not null default '{}',
  dados_sensiveis          boolean not null default false,
  titulares_estimados      integer check (titulares_estimados is null or titulares_estimados >= 0),
  risco                    text not null check (risco in ('low','relevant')),
  medidas                  text not null,
  prazo_comunicacao_em     timestamptz,
  anpd_comunicado_em       timestamptz,
  titulares_comunicados_em timestamptz,
  chaves_rotacionadas      boolean not null default false,
  sessoes_revogadas        boolean not null default false,
  status                   text not null default 'open' check (status in ('open','contained','closed')),
  registrado_por           uuid references public.profiles (id) on delete set null,
  criado_em                timestamptz not null default now(),
  constraint incidentes_prazo_quando_relevante check (
    risco <> 'relevant' or prazo_comunicacao_em is not null
  )
);

comment on table lgpd.incidentes is 'Incidente de seguranca com dado pessoal: deteccao, categorias afetadas, risco, medidas e comunicacao. Risco relevant dispara o prazo de tres dias uteis da Resolucao CD/ANPD 15/2024. As marcas de chaves rotacionadas e sessoes revogadas vem do runbook do drk-app-template do DRK Aachen. A descricao nunca traz dado pessoal.';

create index if not exists incidentes_status_detectado_em_idx on lgpd.incidentes (status, detectado_em desc);

alter table lgpd.incidentes enable row level security;

create policy incidentes_select_administrador on lgpd.incidentes for select to authenticated
  using (
    (select public.autorizar('operacao.administrar'::public.permissao, null))
    or (select public.autorizar('trilha.ler_completa'::public.permissao, null))
  );

create policy incidentes_insert_administrador on lgpd.incidentes for insert to authenticated
  with check (
    (select private.is_workspace_member(workspace_id))
    and (select public.autorizar('operacao.administrar'::public.permissao, null))
    and (select private.exige_aal2())
    and registrado_por = (select auth.uid())
  );

create policy incidentes_update_administrador on lgpd.incidentes for update to authenticated
  using ((select public.autorizar('operacao.administrar'::public.permissao, null)))
  with check (
    (select public.autorizar('operacao.administrar'::public.permissao, null))
    and (select private.exige_aal2())
  );

revoke all on table lgpd.incidentes from public, anon;
grant select, insert, update on table lgpd.incidentes to authenticated;

-- ============================================================================
-- 18. Exportacao e anonimizacao por titular
-- ============================================================================

create or replace function lgpd.anonimizar_titular(p_user_id uuid)
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  v_ws       uuid;
  v_pendente integer;
  v_linhas   integer := 0;
  v_n        integer;
  v_email    text;
begin
  if not (select public.autorizar('lgpd.responder_titular'::public.permissao, null)) then
    raise exception 'So o encarregado ou o administrador anonimiza um titular.' using errcode = '42501';
  end if;
  if coalesce((select auth.jwt() ->> 'aal'), 'aal1') <> 'aal2' then
    raise exception 'A anonimizacao exige sessao com segundo fator.' using errcode = '42501';
  end if;

  select w.id into v_ws from public.workspaces w order by w.created_at limit 1;

  -- Retencao legal vigente bloqueia: dez anos da prestacao de contas (MROSC,
  -- art. 68) e o que a Diretoria fixar em lgpd.operacoes e tipos_documentais.
  -- So conta documento cujo tipo tem prazo efetivamente fixado: tipo com
  -- public.tipos_documentais.prazo_pendente_decisao verdadeiro nunca e
  -- fundamento de recusa ao titular.
  select count(*) into v_pendente
    from public.assinaturas s
    join public.documentos d         on d.id = s.documento_id
    join public.tipos_documentais td on td.id = d.tipo_documental_id
   where s.signatario_id = p_user_id
     and not td.prazo_pendente_decisao
     and d.retencao_ate is not null
     and d.retencao_ate > current_date;
  if v_pendente > 0 then
    raise exception 'Ha % documento(s) com retencao legal vigente: a eliminacao e recusada com a hipotese do art. 16 da LGPD.', v_pendente
      using errcode = '42501';
  end if;

  -- 1. Perfil: saem o dado pessoal e a chave de ligacao entre UUID e pessoa. A
  -- linha nunca e apagada, porque public.grupos.dono_id, public.avisos.autor_id,
  -- public.grupo_membros.user_id, public.aviso_leituras.user_id,
  -- public.autorizacoes.solicitante_id, public.assinaturas.signatario_id e
  -- public.convites.criado_por a referenciam com on delete restrict ou sem
  -- clausula. competencias e interesses sao not null e voltam a lista vazia;
  -- full_name e username sao not null na tabela da Redacao e por isso recebem
  -- marcador sem dado pessoal, derivado do uuid no caso do username.
  update public.profiles
     set full_name = '[eliminado]', nome_social = null, email_contato = null, telefone = null,
         apresentacao = null, competencias = '{}', interesses = '{}', avatar_path = null,
         username = 'anon-' || left(p_user_id::text, 8)
   where id = p_user_id;
  get diagnostics v_n = row_count;
  v_linhas := v_linhas + v_n;

  -- 2. Ficha restrita inteira: CPF, RG, nascimento, endereco e dados de saude.
  delete from public.profiles_restritos where profile_id = p_user_id;
  get diagnostics v_n = row_count;
  v_linhas := v_linhas + v_n;

  -- 3. Convites emitidos ao titular. public.convites.email e not null e o check
  -- exige arroba: em lugar de nulo entra endereco derivado do id do convite,
  -- que nao carrega dado pessoal nenhum.
  select lower(u.email) into v_email from auth.users u where u.id = p_user_id;
  update public.convites c
     set email = 'anonimizado-' || left(c.id::text, 8) || '@invalido.local'
   where c.aceito_por = p_user_id
      or (v_email is not null and lower(c.email) = v_email);
  get diagnostics v_n = row_count;
  v_linhas := v_linhas + v_n;

  -- 4. Mensagens diretas de que o titular e autor. public.messages.body e not
  -- null, entao entra o mesmo marcador sem dado pessoal; o trigger
  -- public.messages_so_lido_em() proibe alterar body, e por isso fica desligado
  -- apenas durante esta transacao de anonimizacao.
  alter table public.messages disable trigger messages_so_lido_em;
  update public.messages set body = '[eliminado]' where author_id = p_user_id;
  get diagnostics v_n = row_count;
  v_linhas := v_linhas + v_n;
  alter table public.messages enable trigger messages_so_lido_em;

  -- 5. Evidencias apagaveis de decisao e de assinatura.
  update public.autorizacao_decisoes
     set ip = null, user_agent = null, motivo = null
   where ator_id = p_user_id;
  get diagnostics v_n = row_count;
  v_linhas := v_linhas + v_n;

  update public.assinaturas
     set ip = null, user_agent = null
   where signatario_id = p_user_id;
  get diagnostics v_n = row_count;
  v_linhas := v_linhas + v_n;

  -- 6. Carimbos de saida.
  update public.profiles
     set desativado_em = coalesce(desativado_em, now()),
         eliminado_em  = coalesce(eliminado_em, now())
   where id = p_user_id;

  -- A cadeia fica com hash e UUID orfao: e assim que a resposta ao titular e sim
  -- sem quebrar o append-only (docs/04, secao 5).
  perform auditoria.registrar_evento_do_sistema(
    v_ws, 'F10', 'profiles', p_user_id, 'titular.anonimizado', null, null,
    jsonb_build_object('estado', 'anonimizado')
  );

  return v_linhas;
end;
$$;
comment on function lgpd.anonimizar_titular(uuid) is 'Atende ao pedido de eliminacao do titular (LGPD art. 18, VI). Exige o encarregado ou o administrador, em sessao com segundo fator. Recusa enquanto houver retencao legal vigente, respondendo com a hipotese do art. 16, e ignora tipo documental com prazo ainda pendente de decisao da Diretoria. Onde a coluna aceita nulo, apaga; onde e obrigatoria (nome, corpo de mensagem, e-mail de convite), grava marcador sem dado pessoal, e o nome de usuario vira anon mais um identificador curto. O que sobra na cadeia de auditoria e um identificador orfao e a impressao digital, nunca dado pessoal, conforme o procedimento de eliminacao de docs/04-rastreabilidade-blockchain.md, secao 6. Devolve quantas linhas foram tratadas e registra titular.anonimizado na trilha.';

create or replace function lgpd.exportar_titular(p_user_id uuid)
returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_json jsonb;
begin
  if p_user_id <> (select auth.uid())
     and not (select public.autorizar('lgpd.responder_titular'::public.permissao, null)) then
    raise exception 'Cada pessoa exporta os proprios dados; o encarregado exporta a pedido.'
      using errcode = '42501';
  end if;

  select jsonb_build_object(
    'perfil', coalesce((select to_jsonb(p) - 'busca'
                           from public.profiles p where p.id = p_user_id), '{}'),
    'perfil_restrito', coalesce((select to_jsonb(r)
                           from public.profiles_restritos r where r.profile_id = p_user_id), '{}'),
    'vinculos', coalesce((select jsonb_agg(to_jsonb(v))
                           from public.vinculos v where v.profile_id = p_user_id), '[]'),
    'formacoes', coalesce((select jsonb_agg(to_jsonb(f))
                           from public.formacoes f where f.profile_id = p_user_id), '[]'),
    'credenciais', coalesce((select jsonb_agg(to_jsonb(c))
                           from public.credenciais c where c.profile_id = p_user_id), '[]'),
    'consentimentos', coalesce((select jsonb_agg(to_jsonb(k))
                           from public.consentimentos k where k.profile_id = p_user_id), '[]'),
    'termos_adesao', coalesce((select jsonb_agg(to_jsonb(t))
                           from public.termos_adesao t where t.profile_id = p_user_id), '[]'),
    'aviso_leituras', coalesce((select jsonb_agg(to_jsonb(l))
                           from public.aviso_leituras l where l.user_id = p_user_id), '[]'),
    'grupo_membros', coalesce((select jsonb_agg(to_jsonb(g))
                           from public.grupo_membros g where g.user_id = p_user_id), '[]'),
    'pedidos_titular', coalesce((select jsonb_agg(to_jsonb(pt))
                           from lgpd.pedidos_titular pt where pt.titular_id = p_user_id), '[]'),
    'pedidos', coalesce((select jsonb_agg(to_jsonb(a) - 'codigo_verificacao')
                           from public.autorizacoes a where a.solicitante_id = p_user_id), '[]'),
    'decisoes', coalesce((select jsonb_agg(to_jsonb(d) - 'ip' - 'user_agent')
                           from public.autorizacao_decisoes d where d.ator_id = p_user_id), '[]'),
    'assinaturas', coalesce((select jsonb_agg(to_jsonb(s) - 'ip' - 'user_agent')
                           from public.assinaturas s where s.signatario_id = p_user_id), '[]'),
    'eventos', coalesce((select jsonb_agg(to_jsonb(e) - 'hash_anterior' - 'hash_linha' - 'ip_hash' - 'user_agent_hash')
                           from auditoria.eventos e where e.ator_id = p_user_id), '[]')
  ) into v_json;

  return v_json;
end;
$$;

comment on function lgpd.exportar_titular(uuid) is 'Exportacao do art. 18, II e V, da LGPD: perfil (sem a coluna gerada busca), dados restritos, vinculos, formacoes, credenciais, consentimentos, termos de adesao, leituras de aviso, grupos, pedidos do canal do titular, pedidos de autorizacao, decisoes, assinaturas e eventos em que a pessoa e ator, sem hash_anterior e hash_linha (que sao da cadeia, nao do titular) e sem IP. E a base da resposta escrita ao titular no prazo de 15 dias do art. 19, II. A Server Action grava o JSON no armazenamento com link assinado de 24 horas e registra titular.exportado.';

revoke all on function lgpd.anonimizar_titular(uuid) from public, anon;
revoke all on function lgpd.exportar_titular(uuid)   from public, anon;
grant execute on function lgpd.anonimizar_titular(uuid) to authenticated;
grant execute on function lgpd.exportar_titular(uuid)   to authenticated;
