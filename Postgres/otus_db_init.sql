create role replicator with login replication password 'pass';

CREATE TABLE IF NOT EXISTS  public.users (
    user_id varchar(50) PRIMARY KEY NOT NULL,
	first_name varchar(40) NOT NULL,
	second_name varchar(40) NOT NULL,
	age integer,
	city varchar(40),
	biography varchar(100)
	);
--CREATE INDEX trgm_name_idx ON public.users USING gin (first_name gin_trgm_ops); 
--CREATE INDEX trgm_sec_name_idx ON public.users USING gin (second_name gin_trgm_ops);

CREATE TABLE IF NOT EXISTS public.accounts
(
    user_id varchar(50) NOT NULL,
    user_login varchar(40) UNIQUE,
    user_password varchar(100),
    CONSTRAINT accounts_pkey PRIMARY KEY (user_id)
);

INSERT INTO users VALUES
('550e8400-e29b-41d4-a716-446655440000', 'Ivanov', 'Ivan', '200', 'Reading', 'Saint Petersburg');

INSERT INTO accounts VALUES
('550e8400-e29b-41d4-a716-446655440000', 'ivan2000', 'ivan2000');

