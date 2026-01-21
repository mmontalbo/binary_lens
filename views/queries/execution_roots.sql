with in_degree as (
  select to_function_id as function_id, count(*) as in_degree
  from call_edges
  group by to_function_id
),
candidates as (
  select
    n.function_id,
    n.name,
    n.signature,
    case
      when lower(n.name) = 'main' then 'main'
      when lower(n.name) in ('_start', 'start', 'entry') then 'entrypoint'
      when coalesce(d.in_degree, 0) = 0 then 'root_candidate'
      else 'unknown'
    end as kind,
    case
      when lower(n.name) in ('main', '_start', 'start', 'entry') then 'known'
      when coalesce(d.in_degree, 0) = 0 then 'unknown'
      else 'unknown'
    end as status
  from callgraph_nodes n
  left join in_degree d on d.function_id = n.function_id
  where lower(n.name) in ('main', '_start', 'start', 'entry')
     or coalesce(d.in_degree, 0) = 0
)
select function_id, name, signature, kind, status
from candidates
order by
  case when status = 'known' then 0 else 1 end,
  function_id
limit 50;
