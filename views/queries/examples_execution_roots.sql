with in_degree as (
  select to_function_id as function_id, count(*) as in_degree
  from call_edges
  group by to_function_id
)
select
  n.function_id,
  n.name,
  case
    when lower(n.name) = 'main' then 'main'
    when lower(n.name) in ('_start', 'start', 'entry') then 'entrypoint'
    when coalesce(d.in_degree, 0) = 0 then 'root_candidate'
    else 'unknown'
  end as kind
from callgraph_nodes n
left join in_degree d on d.function_id = n.function_id
where lower(n.name) in ('main', '_start', 'start', 'entry')
   or coalesce(d.in_degree, 0) = 0
order by kind, n.function_id
limit 25;
