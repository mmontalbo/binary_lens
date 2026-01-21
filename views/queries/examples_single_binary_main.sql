select
  function_id,
  name,
  signature
from callgraph_nodes
where name is not null
  and lower(name) like 'single_binary_main_%'
order by function_id
limit 25;
