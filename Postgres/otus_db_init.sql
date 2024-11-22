CREATE TABLE IF NOT EXISTS  public.users (
	user_id UUID PRIMARY KEY NOT NULL,
	first_name varchar(40),
	second_name varchar(40),
	birthdate date,
	biography varchar(100),
	city varchar(40)
	);

CREATE TABLE IF NOT EXISTS public.accounts
(
    user_id uuid NOT NULL,
    user_login varchar(40) UNIQUE,
    user_password varchar(100),
    CONSTRAINT accounts_pkey PRIMARY KEY (user_id)
);

INSERT INTO users VALUES
('550e8400-e29b-41d4-a716-446655440000'::UUID, 'Ivanov', 'Ivan', '01.01.2000', 'Reading', 'Saint Petersburg');

INSERT INTO accounts VALUES
('550e8400-e29b-41d4-a716-446655440000'::UUID, 'ivan2000', 'ivan2000');