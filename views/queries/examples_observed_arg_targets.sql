with observed_callsites as (
  select distinct callsite_id
  from callsite_arg_observations
),
observed_callees as (
  select
    e.callsite_id,
    n.name as callee
  from call_edges e
  join callgraph_nodes n on n.function_id = e.to_function_id
  join observed_callsites o on o.callsite_id = e.callsite_id
  where n.name is not null
)
select
  lower(callee) as callee,
  count(distinct callsite_id) as callsite_count
from observed_callees
group by lower(callee)
order by callsite_count desc, callee
limit 25;
