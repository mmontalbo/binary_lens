select
  e.callsite_id,
  n.name as callee,
  a.int_value as exit_code
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
left join callsite_arg_observations a
  on a.callsite_id = e.callsite_id
 and a.kind = 'int'
 and a.arg_index = 0
 and a.status = 'known'
where lower(n.name) in ('exit', '_exit', 'exit_group', '_exit_group', 'abort')
order by e.callsite_id
limit 25;
