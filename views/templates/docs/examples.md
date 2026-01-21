# DuckDB recipes: `{{binary_name}}`

These examples show how to query Parquet facts with DuckDB.

Before running queries, load tables:

```sh
duckdb -c ".read views/queries/load_tables.sql"
```

## Example: execution roots

```sql
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
```

Results (first 25 rows):

{{example_execution_roots_table}}

## Recipe: reachability from roots

```sql
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
```

Results (first 25 rows):

{{example_reachability_table}}

## Recipe: env vars touched

```sql
select distinct
  s.value as env_var,
  e.callsite_id
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
join callsite_arg_observations a
  on a.callsite_id = e.callsite_id
 and a.kind = 'string'
 and a.arg_index = 0
 and a.status = 'resolved'
join strings s on s.string_id = a.string_id
where lower(n.name) in ('getenv', 'secure_getenv', '__getenv', 'getenv_s')
order by env_var
limit 25;
```

Results (first 25 rows):

{{example_env_vars_table}}

## Recipe: stderr/output templates (heuristic)

```sql
select
  e.callsite_id,
  n.name as callee,
  s.value as template
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
join callsite_arg_observations a
  on a.callsite_id = e.callsite_id
 and a.kind = 'string'
 and a.status = 'resolved'
join strings s on s.string_id = a.string_id
where lower(n.name) in ('fprintf', 'printf', 'vfprintf', 'vprintf', 'puts', 'fputs')
order by e.callsite_id
limit 25;
```

Results (first 25 rows):

{{example_output_templates_table}}

## Recipe: usage-marker strings

```sql
select string_id, value
from strings
where list_contains(tags, 'usage')
order by string_id
limit 25;
```

Results (first 25 rows):

{{example_usage_strings_table}}

## Recipe: exit callsites

```sql
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
```

Results (first 25 rows):

{{example_exit_callsites_table}}

## Recipe: top external calls

```sql
select n.name, count(*) as callsites
from call_edges e
join callgraph_nodes n on n.function_id = e.to_function_id
where n.is_external = true
group by n.name
order by callsites desc
limit 25;
```

Results (first 25 rows):

{{example_top_external_calls_table}}
