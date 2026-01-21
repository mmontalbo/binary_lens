select n.name, count(*) as callsites
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
where n.is_external = true
group by n.name
order by callsites desc, n.name
limit 25;
