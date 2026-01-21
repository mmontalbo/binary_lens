select
  e.callsite_id,
  n.name as callee,
  a.arg_index,
  coalesce(s.value, a.string_value) as token,
  a.status,
  a.basis
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
join callsite_arg_observations a
  on a.callsite_id = e.callsite_id
 and a.kind = 'string'
left join strings s on s.string_id = a.string_id
where lower(n.name) in ('strcmp', 'strncmp', 'strcasecmp', 'strncasecmp')
  and coalesce(s.value, a.string_value) is not null
  and coalesce(s.value, a.string_value) <> ''
order by e.callsite_id, a.arg_index, token
limit 25;
