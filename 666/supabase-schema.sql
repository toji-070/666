-- Run this setup in a new, dedicated Supabase project for 666.
-- It creates the community schema; it does not delete any existing 5005 data.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null check (char_length(username) between 3 and 20),
  bio text not null default '' check (char_length(bio) <= 280),
  avatar_url text,
  background_url text,
  background_type text,
  user_rank text not null default 'Üye',
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.profiles
  add column if not exists bio text not null default '',
  add column if not exists avatar_url text,
  add column if not exists background_url text,
  add column if not exists background_type text,
  add column if not exists user_rank text not null default 'Üye',
  add column if not exists is_admin boolean not null default false;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'profiles_bio_length_check'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_bio_length_check check (char_length(bio) <= 280);
  end if;
end $$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'profiles_user_rank_check'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_user_rank_check
      check (user_rank in ('Üye', 'Çaylak', 'Aktif', 'Uzman', 'Moderatör', 'Kıdemli'));
  end if;
end $$;

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'rank'
  ) then
    execute $migration$
      update public.profiles
      set user_rank = "rank"
      where "rank" in ('Üye', 'Çaylak', 'Aktif', 'Uzman', 'Moderatör', 'Kıdemli')
        and user_rank = 'Üye'
    $migration$;
  end if;
end $$;

create unique index if not exists profiles_username_lower_unique
  on public.profiles (lower(username));

insert into public.profiles (id, username)
select au.id,
       case
         when char_length(coalesce(au.raw_user_meta_data ->> 'username', '')) between 3 and 20
           then au.raw_user_meta_data ->> 'username'
         else 'user-' || left(au.id::text, 8)
       end
from auth.users au
where not exists (select 1 from public.profiles p where p.id = au.id)
on conflict do nothing;

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id) on delete cascade,
  title text not null check (char_length(title) between 1 and 100),
  body text not null check (char_length(body) between 1 and 8000),
  category text not null check (category in ('code', 'report', 'general')),
  created_at timestamptz not null default now()
);

create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  body text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);

create table if not exists public.likes (
  post_id uuid not null references public.posts (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create table if not exists public.follows (
  follower_id uuid not null references public.profiles (id) on delete cascade,
  followed_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, followed_id),
  check (follower_id <> followed_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles (id) on delete cascade,
  recipient_id uuid references public.profiles (id) on delete cascade,
  body text not null check (char_length(body) between 1 and 1000),
  media_path text,
  media_type text,
  created_at timestamptz not null default now(),
  check (recipient_id is null or recipient_id <> sender_id)
);

alter table public.messages
  add column if not exists media_path text,
  add column if not exists media_type text;

create index if not exists posts_created_at_idx on public.posts (created_at desc);
create index if not exists comments_post_created_at_idx on public.comments (post_id, created_at);
create index if not exists messages_created_at_idx on public.messages (created_at);
create index if not exists messages_sender_recipient_idx on public.messages (sender_id, recipient_id);
create index if not exists messages_recipient_sender_idx on public.messages (recipient_id, sender_id);

alter table public.profiles enable row level security;
alter table public.posts enable row level security;
alter table public.comments enable row level security;
alter table public.likes enable row level security;
alter table public.follows enable row level security;
alter table public.messages enable row level security;

revoke all on public.profiles, public.posts, public.comments, public.likes, public.follows, public.messages
  from anon, authenticated;

grant select on public.profiles, public.follows, public.messages
  to anon, authenticated;
revoke select on public.posts, public.comments, public.likes from anon;
grant select on public.posts, public.comments, public.likes to authenticated;
grant insert (id, username) on public.profiles to authenticated;
grant update (username, bio, avatar_url, background_url, background_type, user_rank) on public.profiles to authenticated;
grant insert, delete on public.posts to authenticated;
grant insert, delete on public.comments to authenticated;
grant insert, delete on public.likes to authenticated;
grant insert, delete on public.follows to authenticated;
grant insert on public.messages to authenticated;

drop policy if exists "Public profiles are readable" on public.profiles;
create policy "Public profiles are readable" on public.profiles
  for select to anon, authenticated using (true);
drop policy if exists "Users create their own profile" on public.profiles;
create policy "Users create their own profile" on public.profiles
  for insert to authenticated with check ((select auth.uid()) = id);

create or replace function public.is_current_user_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and is_admin
  );
$$;

revoke all on function public.is_current_user_admin() from public;
grant execute on function public.is_current_user_admin() to authenticated;

drop policy if exists "Users update their own profile" on public.profiles;
create policy "Users update their own profile" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id or (select public.is_current_user_admin()))
  with check ((select auth.uid()) = id or (select public.is_current_user_admin()));

create or replace function public.prevent_non_admin_rank_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.user_rank is distinct from old.user_rank
     and not public.is_current_user_admin() then
    raise exception 'Only administrators can assign ranks';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_profile_rank on public.profiles;
drop trigger if exists protect_profile_user_rank on public.profiles;
create trigger protect_profile_rank
  before update of user_rank on public.profiles
  for each row execute function public.prevent_non_admin_rank_change();

drop policy if exists "Posts are readable" on public.posts;
create policy "Posts are readable" on public.posts
  for select to authenticated using (true);
drop policy if exists "Users create their own posts" on public.posts;
create policy "Users create their own posts" on public.posts
  for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users delete their own posts" on public.posts;
create policy "Users delete their own posts" on public.posts
  for delete to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "Comments are readable" on public.comments;
create policy "Comments are readable" on public.comments
  for select to authenticated using (true);
drop policy if exists "Users create their own comments" on public.comments;
create policy "Users create their own comments" on public.comments
  for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users delete their own comments" on public.comments;
create policy "Users delete their own comments" on public.comments
  for delete to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "Likes are readable" on public.likes;
create policy "Likes are readable" on public.likes
  for select to authenticated using (true);
drop policy if exists "Users like as themselves" on public.likes;
create policy "Users like as themselves" on public.likes
  for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users remove their own likes" on public.likes;
create policy "Users remove their own likes" on public.likes
  for delete to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "Follows are readable" on public.follows;
create policy "Follows are readable" on public.follows
  for select to anon, authenticated using (true);
drop policy if exists "Users follow as themselves" on public.follows;
create policy "Users follow as themselves" on public.follows
  for insert to authenticated with check ((select auth.uid()) = follower_id);
drop policy if exists "Users remove their own follows" on public.follows;
create policy "Users remove their own follows" on public.follows
  for delete to authenticated using ((select auth.uid()) = follower_id);

drop policy if exists "Users read public and addressed messages" on public.messages;
create policy "Users read public and addressed messages" on public.messages
  for select to anon, authenticated
  using (
    recipient_id is null
    or (select auth.uid()) = sender_id
    or (select auth.uid()) = recipient_id
  );
drop policy if exists "Users send messages as themselves" on public.messages;
create policy "Users send messages as themselves" on public.messages
  for insert to authenticated
  with check (
    (select auth.uid()) = sender_id
    and (recipient_id is null or (select auth.uid()) <> recipient_id)
  );

create or replace function public.handle_new_golge_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  requested_username text;
begin
  requested_username := btrim(coalesce(new.raw_user_meta_data ->> 'username', ''));
  if char_length(requested_username) not between 3 and 20 then
    requested_username := 'user-' || left(new.id::text, 8);
  end if;
  begin
    insert into public.profiles (id, username)
    values (new.id, requested_username)
    on conflict (id) do nothing;
  exception when unique_violation then
    insert into public.profiles (id, username)
    values (new.id, 'user-' || left(new.id::text, 8))
    on conflict (id) do nothing;
  end;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_golge on auth.users;
create trigger on_auth_user_created_golge
  after insert on auth.users
  for each row execute function public.handle_new_golge_user();

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 5242880, array['image/jpeg', 'image/png', 'image/webp', 'image/gif'])
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Avatar images are publicly readable" on storage.objects;
create policy "Avatar images are publicly readable" on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'avatars');

drop policy if exists "Users upload their own avatar" on storage.objects;
create policy "Users upload their own avatar" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('profile-backgrounds', 'profile-backgrounds', true, 20971520,
        array['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm'])
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Profile backgrounds are publicly readable" on storage.objects;
create policy "Profile backgrounds are publicly readable" on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'profile-backgrounds');

drop policy if exists "Users upload their own profile backgrounds" on storage.objects;
create policy "Users upload their own profile backgrounds" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'profile-backgrounds'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Users delete their own profile backgrounds" on storage.objects;
create policy "Users delete their own profile backgrounds" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'profile-backgrounds'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('chat-media', 'chat-media', false, 20971520, array['image/gif', 'video/mp4', 'video/webm'])
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Users upload their own chat media" on storage.objects;
create policy "Users upload their own chat media" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'chat-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Chat media is readable by conversation members" on storage.objects;
create policy "Chat media is readable by conversation members" on storage.objects
  for select to anon, authenticated
  using (
    bucket_id = 'chat-media'
    and exists (
      select 1
      from public.messages m
      where m.media_path = name
        and (
          m.recipient_id is null
          or m.sender_id = (select auth.uid())
          or m.recipient_id = (select auth.uid())
        )
    )
  );

drop policy if exists "Users delete their own chat media" on storage.objects;
create policy "Users delete their own chat media" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'chat-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Users update their own avatar" on storage.objects;
create policy "Users update their own avatar" on storage.objects
  for update to authenticated
  using (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  )
  with check (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Users delete their own avatar" on storage.objects;
create policy "Users delete their own avatar" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

do $$
begin
  alter publication supabase_realtime add table public.profiles;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.posts;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.comments;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.likes;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.follows;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.messages;
exception when duplicate_object then null;
end $$;
