with decomp as (
  select
    j."function".address as function_id,
    u.name as function_name,
    j.lines
  from read_json_auto('evidence/decomp/*.json') as j
  join usage_help_functions u on u.function_id = j."function".address
  where j.lines is not null
),
lines as (
  select
    d.function_id,
    d.function_name,
    t.line_no,
    t.line
  from decomp d,
    unnest(d.lines) with ordinality as t(line, line_no)
  where t.line is not null
),
tagged_lines as (
  select
    function_id,
    function_name,
    line_no,
    line,
    (
      line_lower like '%dcngettext(%'
      or line_lower like '%dcngettext (%'
      or line_lower like '%dngettext(%'
      or line_lower like '%dngettext (%'
      or line_lower like '%dcgettext(%'
      or line_lower like '%dcgettext (%'
      or line_lower like '%dgettext(%'
      or line_lower like '%dgettext (%'
      or line_lower like '%ngettext(%'
      or line_lower like '%ngettext (%'
      or line_lower like '%gettext(%'
      or line_lower like '%gettext (%'
    ) as is_gettext_call
  from (
    select
      l.function_id as function_id,
      l.function_name as function_name,
      l.line_no as line_no,
      l.line as line,
      lower(l.line) as line_lower
    from lines l
  ) t
),
filtered_lines as (
  select
    function_id,
    function_name,
    line_no,
    line
  from (
    select
      function_id,
      function_name,
      line_no,
      line,
      is_gettext_call,
      lag(is_gettext_call) over (partition by function_id order by line_no) as prev_is_gettext_call
    from tagged_lines
  ) t
  where is_gettext_call or coalesce(prev_is_gettext_call, false)
),
literals as (
  select
    f.function_id,
    f.function_name,
    f.line_no,
    s.string_no,
    trim(both '"' from s.literal) as literal_raw
  from filtered_lines f,
    unnest(regexp_extract_all(f.line, '"(?:[^"\\\\]|\\\\.)*"')) with ordinality as s(literal, string_no)
),
decoded as (
  select
    function_id,
    function_name,
    line_no,
    string_no,
    literal_raw,
    replace(
      replace(
        replace(
          replace(
            replace(
              replace(literal_raw, chr(92) || 'n', chr(10)),
              chr(92) || 't', chr(9)
            ),
            chr(92) || 'r', chr(13)
          ),
          chr(92) || chr(34), chr(34)
        ),
        chr(92) || chr(39), chr(39)
      ),
      chr(92) || chr(92), chr(92)
    ) as literal_decoded
  from literals
)
select
  function_id,
  function_name,
  line_no,
  string_no,
  literal_raw,
  literal_decoded,
  replace(
    replace(
      replace(literal_decoded, chr(13), chr(92) || 'r'),
      chr(10), chr(92) || 'n'
    ),
    chr(9), chr(92) || 't'
  ) as literal_display
from decoded
where literal_raw is not null
  and literal_raw <> ''
order by function_id, line_no, string_no
limit 50;
