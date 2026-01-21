select
  table_name,
  column_name,
  data_type
from information_schema.columns
where table_schema = 'main'
  and table_name in (
    'callgraph_nodes',
    'call_edges',
    'callsites',
    'callsite_arg_observations',
    'strings'
  )
order by table_name, ordinal_position;
