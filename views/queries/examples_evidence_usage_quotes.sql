with decomp as (
  select
    j."function".address as function_id,
    u.name as function_name,
    j.lines
  from read_json_auto('evidence/decomp/*.json') as j
  join usage_help_functions u on u.function_id = j."function".address
  where j.lines is not null
),
quoted as (
  select
    d.function_id,
    d.function_name,
    regexp_extract(line, '"([^"]{3,})"', 1) as quoted
  from decomp d,
    unnest(d.lines) as t(line)
  where line is not null
)
select distinct
  function_id,
  function_name,
  quoted
from quoted
where quoted is not null
  and quoted <> ''
  and (
    lower(quoted) like '%usage%'
    or lower(quoted) like '%help%'
    or lower(quoted) like '%options%'
  )
order by function_id, quoted
limit 25;
