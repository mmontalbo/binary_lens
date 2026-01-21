select
  function_id,
  name,
  signature
from usage_help_functions
order by function_addr_int
limit 25;
