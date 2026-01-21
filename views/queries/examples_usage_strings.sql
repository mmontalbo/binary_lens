select string_id, value
from strings
where list_contains(tags, 'usage')
order by string_id
limit 25;
