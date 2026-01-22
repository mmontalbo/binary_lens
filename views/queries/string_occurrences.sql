-- String provenance by callsite argument observation.
-- Canonical ordering: callsite_addr_int, arg_index, callsite_id, to_function_id, observation_id.
select
  a.callsite_id,
  c.callsite_addr_int,
  c.from_function_id,
  caller.name as from_function_name,
  e.to_function_id,
  callee.name as to_function_name,
  a.arg_index,
  a.status,
  a.basis,
  a.string_id,
  coalesce(s.value, a.string_value) as string_value,
  coalesce(s.address, a.address) as string_address,
  s.tags as tags,
  a.provider_callsite_id
from callsite_arg_observations a
left join callsites c on c.callsite_id = a.callsite_id
left join call_edges e on e.callsite_id = a.callsite_id
left join callgraph_nodes caller on caller.function_id = c.from_function_id
left join callgraph_nodes callee on callee.function_id = e.to_function_id
left join strings s on s.string_id = a.string_id
where a.kind = 'string'
order by
  c.callsite_addr_int,
  a.arg_index,
  a.callsite_id,
  e.to_function_id,
  a.observation_id;
