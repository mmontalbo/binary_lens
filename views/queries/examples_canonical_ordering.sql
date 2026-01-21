select
  c.callsite_id,
  c.callsite_addr_int,
  c.from_function_id,
  n.function_addr_int,
  n.name as from_name
from callsites c
left join callgraph_nodes n on n.function_id = c.from_function_id
order by n.function_addr_int, c.callsite_addr_int
limit 25;
