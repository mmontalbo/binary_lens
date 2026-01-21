with evidence_entries as (
  select
    entry.function_id as function_id,
    entry.name as evidence_name,
    entry.truncated as truncated,
    entry.excerpt_line_count as excerpt_line_count,
    entry.max_lines_applied as max_lines_applied,
    entry.line_count as line_count
  from read_json_auto('evidence/index.json') as idx,
    unnest(idx.entries) as t(entry)
),
string_args as (
  select
    e.from_function_id as function_id,
    count(*) as string_arg_total,
    sum(case when a.status = 'resolved' then 1 else 0 end) as string_arg_resolved,
    sum(case when a.status = 'unresolved' then 1 else 0 end) as string_arg_unresolved,
    sum(case when a.status = 'unknown' then 1 else 0 end) as string_arg_unknown,
    sum(case when a.basis = 'string_direct' then 1 else 0 end) as string_arg_direct,
    sum(case when a.basis = 'string_gettext' then 1 else 0 end) as string_arg_gettext
  from call_edges e
  join callsite_arg_observations a
    on a.callsite_id = e.callsite_id
   and a.kind = 'string'
  group by e.from_function_id
)
select
  u.function_id,
  u.name,
  case
    when ev.function_id is null then 'missing'
    else 'present'
  end as evidence,
  ev.truncated,
  ev.excerpt_line_count,
  ev.max_lines_applied,
  ev.line_count,
  coalesce(sa.string_arg_total, 0) as string_arg_total,
  coalesce(sa.string_arg_resolved, 0) as string_arg_resolved,
  coalesce(sa.string_arg_direct, 0) as string_arg_direct,
  coalesce(sa.string_arg_gettext, 0) as string_arg_gettext,
  coalesce(sa.string_arg_unresolved, 0) as string_arg_unresolved,
  coalesce(sa.string_arg_unknown, 0) as string_arg_unknown
from usage_help_functions u
left join evidence_entries ev on ev.function_id = u.function_id
left join string_args sa on sa.function_id = u.function_id
order by u.function_addr_int
limit 25;
