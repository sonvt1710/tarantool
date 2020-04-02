test_run = require('test_run').new()
engine = test_run:get_cfg('engine')
--
-- Make sure that when inserting, values are inserted in the given
-- order when ephemeral space is used.
--
box.execute('CREATE TABLE t (i INT PRIMARY KEY AUTOINCREMENT);')
--
-- In order for this INSERT to use the ephemeral space, we created
-- this trigger.
--
box.execute('CREATE TRIGGER r AFTER INSERT ON t FOR EACH ROW BEGIN SELECT 1; END')
box.execute('INSERT INTO t VALUES (1), (NULL), (10), (NULL), (NULL), (3), (NULL);')
box.execute('SELECT * FROM t;')
box.execute('DROP TABLE t;')
