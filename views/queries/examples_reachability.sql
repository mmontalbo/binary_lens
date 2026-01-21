with recursive
roots as (
  select function_id
  from callgraph_nodes
  where lower(name) = 'main'
),
reach(function_id) as (
  select function_id from roots
  union
  select e.to_function_id
  from reach r
  join call_edges e on e.from_function_id = r.function_id
)
select distinct r.function_id, n.name
from reach r
left join callgraph_nodes n on n.function_id = r.function_id
order by r.function_id
limit 25;
