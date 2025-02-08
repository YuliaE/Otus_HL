--CREATE DATABASE otus_db;

CREATE TABLE IF NOT EXISTS  users (
    user_id     varchar(50) PRIMARY KEY NOT NULL,
	first_name  varchar(40) NOT NULL,
	second_name varchar(40) NOT NULL,
	age         integer,
	city        varchar(40),
	biography   varchar(100)
	);
--CREATE INDEX trgm_name_idx ON public.users USING gin (first_name gin_trgm_ops); 

CREATE TABLE IF NOT EXISTS accounts
(
    user_id       varchar(50) NOT NULL,
    user_login    varchar(40) UNIQUE,
    user_password varchar(100),
    CONSTRAINT accounts_pkey PRIMARY KEY (user_id)
);

CREATE TABLE IF NOT EXISTS posts
(
    post_id BIGSERIAL PRIMARY KEY,
    user_id varchar(50),
    post varchar(3000)
);

CREATE TABLE IF NOT EXISTS dialogs
(
    dialog_id   BIGSERIAL PRIMARY KEY,
    dialog_text varchar(3000),
    user_to     varchar(50) NOT NULL,
    user_from   varchar(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS friendships
(
    friendship_id   BIGSERIAL PRIMARY KEY,
    user_id1    varchar(50) NOT NULL REFERENCES users (user_id),
    user_id2   varchar(50) NOT NULL REFERENCES users (user_id)
);

-- insert into dialogs(dialog_text, user_to, user_from)
-- select
--     left(md5(i::text), 20),
--     md5(random()::text),
--     md5(random()::text)
-- from generate_series(1, 1000000) s(i);


INSERT INTO users VALUES
('550e8400-e29b-41d4-a716-446655440000', 'Ivanov', 'Ivan', '200', 'Reading', 'Saint Petersburg');
INSERT INTO users VALUES
('ed40b849-fd72-4601-afdb-00d1031beb9c', 'Smirnov', 'Ivan', '200', 'Reading', 'Saint Petersburg');
INSERT INTO users VALUES
('aa40b849-fd72-4601-afdb-00d1031beb9c', 'Petrov', 'Ivan', '200', 'Reading', 'Saint Petersburg');

INSERT INTO friendships(user_id1, user_id2) VALUES
('550e8400-e29b-41d4-a716-446655440000','ed40b849-fd72-4601-afdb-00d1031beb9c');

INSERT INTO accounts VALUES
('550e8400-e29b-41d4-a716-446655440000', 'ivan2000', 'ivan2000');

-- select * from citus_shards;

