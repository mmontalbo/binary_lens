select distinct
  s.value as env_var,
  e.callsite_id
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
join callsite_arg_observations a
  on a.callsite_id = e.callsite_id
 and a.kind = 'string'
 and a.arg_index = 0
 and a.status = 'resolved'
join strings s on s.string_id = a.string_id
where lower(n.name) in ('getenv', 'secure_getenv', '__getenv', 'getenv_s')
order by env_var, e.callsite_id
limit 25;
