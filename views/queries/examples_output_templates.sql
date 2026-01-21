select
  e.callsite_id,
  n.name as callee,
  s.value as template
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
join callsite_arg_observations a
  on a.callsite_id = e.callsite_id
 and a.kind = 'string'
 and a.status = 'resolved'
join strings s on s.string_id = a.string_id
where lower(n.name) in ('fprintf', 'printf', 'vfprintf', 'vprintf', 'puts', 'fputs')
order by e.callsite_id
limit 25;
