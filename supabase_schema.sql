-- Supabase PostgreSQL starter schema.
-- Create users through Supabase Auth; never store plaintext passwords in these tables.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  username text unique not null,
  role text not null default 'member' check (role in ('admin','member')),
  responsibility text,
  rank_title text,
  degree text,
  father_name text,
  age integer check (age is null or age between 16 and 100),
  created_at timestamptz not null default now()
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id),
  subject text not null,
  body text not null,
  attachment_path text,
  created_at timestamptz not null default now()
);
create table if not exists public.message_recipients (
  message_id uuid references public.messages(id) on delete cascade,
  recipient_id uuid references public.profiles(id) on delete cascade,
  read_at timestamptz,
  primary key(message_id,recipient_id)
);
create table if not exists public.message_replies (
  id uuid primary key default gen_random_uuid(),
  message_id uuid not null references public.messages(id) on delete cascade,
  sender_id uuid not null references public.profiles(id),
  body text not null,
  created_at timestamptz not null default now()
);
create table if not exists public.activity_records (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  title text not null,
  category text not null,
  description text not null,
  created_at timestamptz not null default now()
);
create table if not exists public.audit_events (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id),
  event_type text not null,
  entity_type text not null,
  entity_id uuid,
  created_at timestamptz not null default now()
);

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='admin') $$;

alter table public.profiles enable row level security;
alter table public.messages enable row level security;
alter table public.message_recipients enable row level security;
alter table public.message_replies enable row level security;
alter table public.activity_records enable row level security;
alter table public.audit_events enable row level security;

create policy "profiles visible to authenticated colleagues" on public.profiles
for select to authenticated using (true);
create policy "admins manage profiles" on public.profiles
for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "users update own limited profile" on public.profiles
for update to authenticated using (id=auth.uid()) with check (id=auth.uid() and role=(select role from public.profiles where id=auth.uid()));

create policy "messages visible to sender or recipients" on public.messages
for select to authenticated using (sender_id=auth.uid() or exists(select 1 from public.message_recipients r where r.message_id=id and r.recipient_id=auth.uid()));
create policy "authenticated users send messages" on public.messages
for insert to authenticated with check (sender_id=auth.uid());
create policy "recipients and sender view recipient states" on public.message_recipients
for select to authenticated using (recipient_id=auth.uid() or exists(select 1 from public.messages m where m.id=message_id and m.sender_id=auth.uid()) or public.is_admin());
create policy "sender adds recipients" on public.message_recipients
for insert to authenticated with check (exists(select 1 from public.messages m where m.id=message_id and m.sender_id=auth.uid()));
create policy "recipient marks own message read" on public.message_recipients
for update to authenticated using (recipient_id=auth.uid()) with check (recipient_id=auth.uid());
create policy "replies visible to message participants" on public.message_replies
for select to authenticated using (exists(select 1 from public.messages m where m.id=message_id and (m.sender_id=auth.uid() or exists(select 1 from public.message_recipients r where r.message_id=m.id and r.recipient_id=auth.uid()))));
create policy "participants reply" on public.message_replies
for insert to authenticated with check (sender_id=auth.uid() and exists(select 1 from public.messages m where m.id=message_id and (m.sender_id=auth.uid() or exists(select 1 from public.message_recipients r where r.message_id=m.id and r.recipient_id=auth.uid()))));
create policy "users view own records and admins view all" on public.activity_records
for select to authenticated using (user_id=auth.uid() or public.is_admin());
create policy "users create own records" on public.activity_records
for insert to authenticated with check (user_id=auth.uid());
create policy "audit events admins only" on public.audit_events
for select to authenticated using (public.is_admin());
create policy "authenticated audit inserts" on public.audit_events
for insert to authenticated with check (actor_id=auth.uid());

-- IMPORTANT:
-- 1) Create the first admin via Supabase Auth, then set profiles.role='admin'
--    using the SQL editor as project owner.
-- 2) Configure private Storage bucket 'message-attachments' and policies that
--    restrict uploads/downloads to message participants.
-- 3) Add server-side Edge Functions for admin user provisioning, push delivery,
--    and audit logging. Never expose the service_role key in the browser.
