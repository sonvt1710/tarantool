test_run = require('test_run').new()
engine = test_run:get_cfg('engine')
_ = box.space._session_settings:update('sql_default_engine', {{'=', 2, engine}})

--
-- gh-3075: Check <ALTER TABLE table ADD COLUMN column> statement.
--
box.execute('CREATE TABLE t1 (a INTEGER PRIMARY KEY);')
box.execute('ALTER TABLE t1 ADD b INTEGER;')

--
-- Can't add column to a view.
--
box.execute('CREATE VIEW v AS SELECT * FROM t1;')
box.execute('ALTER TABLE v ADD b INTEGER;')
box.execute('DROP VIEW v;')

--
-- Check column constraints typing and work.
--
box.execute('CREATE TABLE t2 (a INTEGER CONSTRAINT pk_constr PRIMARY KEY);')
box.execute('ALTER TABLE t2 DROP CONSTRAINT pk_constr')
test_run:cmd("setopt delimiter ';'");
box.execute([[ALTER TABLE t2 ADD b INTEGER CONSTRAINT pk_constr PRIMARY KEY
                                   CHECK (b > 0)
                                   REFERENCES t1(a)
                                   CONSTRAINT u_constr UNIQUE]])
test_run:cmd("setopt delimiter ''");
box.execute('INSERT INTO t1 VALUES (1, 1);')
box.execute('INSERT INTO t2 VALUES (1, 1);')
box.execute('INSERT INTO t2 VALUES (1, 1);')

box.execute('INSERT INTO t1 VALUES (0, 1);')
box.execute('INSERT INTO t2 VALUES (2, 0);')

box.execute('INSERT INTO t2 VALUES (2, 3);')

box.execute('DROP TABLE t2;')

--
-- Check AUTOINCREMENT work.
--
box.execute("CREATE TABLE t2(a INTEGER CONSTRAINT pk PRIMARY KEY);")
box.execute("ALTER TABLE t2 DROP CONSTRAINT pk;")
box.execute("ALTER TABLE t2 ADD b INTEGER PRIMARY KEY AUTOINCREMENT;")
box.execute("ALTER TABLE t2 ADD c INTEGER AUTOINCREMENT;")

box.execute('DROP TABLE t2;')

--
-- Check clauses after column typing and work.
--
box.execute('CREATE TABLE t2 (a INTEGER PRIMARY KEY, b INTEGER);')
test_run:cmd("setopt delimiter ';'");
box.execute([[ALTER TABLE t2 ADD c TEXT NOT NULL DEFAULT ('a')
                                   COLLATE "unicode_ci";]]);
test_run:cmd("setopt delimiter ''");
box.execute('INSERT INTO t2(a, b) VALUES (1, 1);')
box.execute('SELECT * FROM t2;')
box.execute('INSERT INTO t2 VALUES (2, 2, NULL);')
box.execute('SELECT * FROM t2 WHERE c LIKE \'A\';')

--
-- Try to add to a non-empty space a [non-]nullable field.
--
box.execute('ALTER TABLE t2 ADD d INTEGER;')
box.execute('ALTER TABLE t2 ADD d TEXT NOT NULL');
box.execute('ALTER TABLE t2 ADD e TEXT NULL');

--
-- Add to a space with no-SQL adjusted or without format.
--
_ = box.schema.space.create('WITHOUT')
box.execute("ALTER TABLE WITHOUT ADD a INTEGER;")
box.execute("DROP TABLE WITHOUT;")

s = box.schema.space.create('NOSQL')
s:format{{name = 'A', type = 'unsigned'}}
box.execute("ALTER TABLE NOSQL ADD b INTEGER")

--
-- Add multiple columns inside a transaction.
--
box.begin()                                                                     \
box.execute('ALTER TABLE t2 ADD f INTEGER;')                                    \
box.execute('ALTER TABLE t2 ADD g INTEGER;')                                    \
box.commit()
