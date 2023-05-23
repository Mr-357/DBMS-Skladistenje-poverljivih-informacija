--SQL Injection-----------------------------------------------------------------------------------------------------

string query = "SELECT * FROM items WHERE owner = '"
                + userName + "' AND itemname = '"
                + ItemName.Text + "'";


userName = "username"

userName = "user' OR 2=2"

"PREPARE query (text,text) AS
SELECT * FROM items WHERE owner = $1 AND itemname = $2";
"EXECUTE query('" + username + "','" + ItemName.Text + "')";

--RBAC-----------------------------------------------------------------------------------------------------

CREATE ROLE not_approved LOGIN PASSWORD 'pass';
CREATE ROLE approved LOGIN PASSWORD 'pass';

CREATE TABLE confidential (
  sensitive_data TEXT
);

GRANT ALL ON confidential TO approved;
REVOKE ALL ON confidential FROM public;

--RLS-----------------------------------------------------------------------------------------------------
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY name ON table_name
    [ AS { PERMISSIVE | RESTRICTIVE } ]
    [ FOR { ALL | SELECT | INSERT | UPDATE | DELETE } ]
    [ TO { role_name | PUBLIC | CURRENT_ROLE | CURRENT_USER | SESSION_USER } [, ...] ]
    [ USING ( using_expression ) ]
    [ WITH CHECK ( check_expression ) ];

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
   email TEXT NOT NULL UNIQUE,
   user_name TEXT NOT NULL UNIQUE
);    

CREATE POLICY user_sel_policy ON users
    FOR SELECT
    USING (true);

CREATE POLICY user_mod ON passwd FOR UPDATE
  USING (current_user = user_name)
  WITH CHECK (
    current_user = user_name AND
    email LIKE '(?:[a-z0-9!#$%''*+/=?^_`{|}~-]+(?:\.
    [a-z0-9!#$%&''*+/=?^_`{|}~-]+)*|
    "(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")
    @(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)
    +[a-z0-9](?:[a-z0-9-]*[a-z0-9])
    ?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}
    (?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]
    :(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'
  );

--pgcrypto-----------------------------------------------------------------------------------------------------

CREATE EXTENSION pgcrypto;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
   email TEXT NOT NULL UNIQUE,
   password TEXT NOT NULL
);

INSERT INTO users (email, password) VALUES (
  'user@mail.com', 
  crypt('securepassword', gen_salt('bf')) 
);

SELECT id 
  FROM users
 WHERE email =  'user@mail.com' 
   AND password = crypt('securepassword', password);
id
----
  1
(1 row)
SELECT id 
  FROM users
 WHERE email =  'user@mail.com'
   AND password = crypt('wrongpassword', password);
id
----
(0 rows)

--pgsodium-----------------------------------------------------------------------------------------------------

CREATE SCHEMA pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;

BEGIN;
SET LOCAL log_statement = 'none';
-- čitanje ključeva ovde
RESET log_statement;
COMMIT;

CREATE TABLE users (
	id bigserial primary key,
	password text,
	key_id uuid not null
);

SECURITY LABEL FOR pgsodium
	ON COLUMN users.password
  IS 'ENCRYPT WITH KEY COLUMN key_id';

INSERT INTO public.users(password, key_id)
	SELECT 'verysecurepassword',id FROM pgsodium.create_key();

SELECT * FROM pgsodium_masks.users;


-- Generisanje ključeva
-- \gset [ime] je psql komanda za čuvanje lokalnih varijabli

SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

-- Kreiramo box_nonce objekat koji služi za čuvanje enkriptovanih podataka

SELECT crypto_box_noncegen() boxnonce \gset

-- Alice čuva svoju poruku, koristi Bobov javni ključ i svoj privatni

SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public', :'alice_secret') box \gset

-- Bob dekriptuje poruku pomoću svog privatnog i javnog ključa druge strane (Alice)

SELECT crypto_box_open(:'box', :'boxnonce', :'alice_public', :'bob_secret');

--postgresql_anonymizer-----------------------------------------------------------------------------------------------------

ALTER DATABASE postgres SET session_preload_libraries = 'anon';
CREATE EXTENSION anon CASCADE;
SELECT anon.init();


CREATE TABLE users_confidential (
    id SERIAL PRIMARY KEY,
   email TEXT NOT NULL UNIQUE,
   password TEXT NOT NULL,
   card TEXT,
   address TEXT
);

SECURITY LABEL FOR anon ON COLUMN users_confidential.card IS
'MASKED WITH FUNCTION anon.partial(card,4,$$$$********$$$$,4)';

SECURITY LABEL FOR anon ON COLUMN users_confidential.address IS
'MASKED WITH FUNCTION anon.fake_address()';

SECURITY LABEL FOR anon ON COLUMN users_confidential.password IS
'MASKED WITH  VALUE ''CONFIDENTIAL''';

SELECT anon.anonymize_database();

CREATE ROLE masked_user LOGIN PASSWORD 'pass';
ALTER ROLE masked_user SET anon.transparent_dynamic_masking = True;
SECURITY LABEL FOR anon ON ROLE masked_user IS 'MASKED';
GRANT USAGE ON SCHEMA public TO masked_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO masked_user;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO masked_user;

