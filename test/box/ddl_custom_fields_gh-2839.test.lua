--
-- gh-2839: allow to store custom fields in field definition.
--
format = {}
format[1] = {name = 'field1', type = 'unsigned'}
format[2] = {'field2', 'unsigned'}
format[3] = {'field3', 'unsigned', custom_field = 'custom_value'}
s = box.schema.create_space('test', {format = format})
s:format()[3].custom_field
s:drop()
