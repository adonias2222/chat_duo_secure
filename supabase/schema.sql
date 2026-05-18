create extension if not exists "pgcrypto";

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  avatar_url text,
  public_key text,
  is_allowed boolean default false,
  online boolean default false,
  last_seen timestamptz default now(),
  created_at timestamptz default now()
);

create table if not exists public.duo_chat (
  id uuid primary key default gen_random_uuid(),
  user_one uuid references public.profiles(id) on delete cascade,
  user_two uuid references public.profiles(id) on delete cascade,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  constraint duo_chat_two_users check (user_one <> user_two)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid references public.duo_chat(id) on delete cascade,
  sender_id uuid references public.profiles(id) on delete cascade,
  type text not null check (type in ('text', 'image', 'video', 'audio')),
  cipher_text text,
  nonce text,
  mac text,
  media_path text,
  file_name text,
  mime_type text,
  file_size bigint,
  seen boolean default false,
  created_at timestamptz default now()
);

create table if not exists public.calls (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid references public.duo_chat(id) on delete cascade,
  caller_id uuid references public.profiles(id) on delete cascade,
  receiver_id uuid references public.profiles(id) on delete cascade,
  type text not null check (type in ('audio', 'video')),
  status text default 'ringing' check (status in ('ringing', 'accepted', 'declined', 'ended')),
  offer jsonb,
  answer jsonb,
  created_at timestamptz default now(),
  ended_at timestamptz
);

create table if not exists public.call_candidates (
  id uuid primary key default gen_random_uuid(),
  call_id uuid references public.calls(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  candidate jsonb not null,
  created_at timestamptz default now()
);

alter table public.profiles enable row level security;
alter table public.duo_chat enable row level security;
alter table public.messages enable row level security;
alter table public.calls enable row level security;
alter table public.call_candidates enable row level security;

create policy "profiles_select_authenticated" on public.profiles for select to authenticated using (true);
create policy "profiles_insert_own" on public.profiles for insert to authenticated with check (auth.uid() = id);
create policy "profiles_update_own" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

create policy "duo_chat_select_members" on public.duo_chat for select to authenticated using (auth.uid() = user_one or auth.uid() = user_two);
create policy "duo_chat_insert_allowed" on public.duo_chat for insert to authenticated with check (
  auth.uid() = user_one and exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_allowed = true)
);
create policy "duo_chat_update_members" on public.duo_chat for update to authenticated using (auth.uid() = user_one or auth.uid() = user_two) with check (auth.uid() = user_one or auth.uid() = user_two);

create policy "messages_select_members" on public.messages for select to authenticated using (
  exists (select 1 from public.duo_chat c where c.id = chat_id and (c.user_one = auth.uid() or c.user_two = auth.uid()))
);
create policy "messages_insert_members" on public.messages for insert to authenticated with check (
  sender_id = auth.uid() and exists (select 1 from public.duo_chat c where c.id = chat_id and (c.user_one = auth.uid() or c.user_two = auth.uid()))
);
create policy "messages_update_members" on public.messages for update to authenticated using (
  exists (select 1 from public.duo_chat c where c.id = chat_id and (c.user_one = auth.uid() or c.user_two = auth.uid()))
);

create policy "calls_select_members" on public.calls for select to authenticated using (auth.uid() = caller_id or auth.uid() = receiver_id);
create policy "calls_insert_caller" on public.calls for insert to authenticated with check (auth.uid() = caller_id);
create policy "calls_update_members" on public.calls for update to authenticated using (auth.uid() = caller_id or auth.uid() = receiver_id) with check (auth.uid() = caller_id or auth.uid() = receiver_id);

create policy "call_candidates_select_members" on public.call_candidates for select to authenticated using (
  exists (select 1 from public.calls c where c.id = call_id and (c.caller_id = auth.uid() or c.receiver_id = auth.uid()))
);
create policy "call_candidates_insert_members" on public.call_candidates for insert to authenticated with check (
  user_id = auth.uid() and exists (select 1 from public.calls c where c.id = call_id and (c.caller_id = auth.uid() or c.receiver_id = auth.uid()))
);

do $$
begin
  begin alter publication supabase_realtime add table public.messages; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.calls; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.call_candidates; exception when duplicate_object then null; end;
end $$;

-- Crie o bucket privado no Storage com o nome: chat-media
create policy "chat_media_select_authenticated" on storage.objects for select to authenticated using (bucket_id = 'chat-media');
create policy "chat_media_insert_authenticated" on storage.objects for insert to authenticated with check (bucket_id = 'chat-media');
create policy "chat_media_update_authenticated" on storage.objects for update to authenticated using (bucket_id = 'chat-media') with check (bucket_id = 'chat-media');
