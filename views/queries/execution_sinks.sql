with exit_targets as (
  select function_id, name
  from callgraph_nodes
  where lower(name) in ('exit', '_exit', 'exit_group', '_exit_group', 'abort')
),
exit_calls as (
  select e.callsite_id, e.from_function_id, e.to_function_id, t.name as target_name
  from call_edges e
  join exit_targets t on t.function_id = e.to_function_id
),
exit_codes as (
  select callsite_id, max(int_value) as exit_code
  from callsite_arg_observations
  where kind = 'int' and arg_index = 0 and status = 'known'
  group by callsite_id
),
main_nodes as (
  select function_id, name
  from callgraph_nodes
  where lower(name) = 'main'
)
select
  c.callsite_id,
  c.from_function_id,
  c.to_function_id,
  c.target_name,
  case
    when lower(c.target_name) = 'abort' then 'abort'
    else 'exit'
  end as kind,
  ec.exit_code as exit_code,
  'known' as status
from exit_calls c
left join exit_codes ec on ec.callsite_id = c.callsite_id
union all
select
  null as callsite_id,
  n.function_id as from_function_id,
  null as to_function_id,
  n.name as target_name,
  'return_from_main' as kind,
  null as exit_code,
  'known' as status
from main_nodes n
union all
select
  null as callsite_id,
  null as from_function_id,
  null as to_function_id,
  'main' as target_name,
  'return_from_main' as kind,
  null as exit_code,
  'unknown' as status
where not exists (select 1 from main_nodes)
order by callsite_id nulls last, from_function_id;
