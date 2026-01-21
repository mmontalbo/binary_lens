select
  coalesce(binary_name, 'unknown') as binary_name,
  coalesce(binary_hashes.sha256, 'unknown') as binary_sha256,
  coalesce(executable_format, 'unknown') as executable_format,
  coalesce(target_arch, 'unknown') as target_arch,
  coalesce(ghidra_version, 'unknown') as ghidra_version,
  coalesce(tool.version, binary_lens_version, 'unknown') as binary_lens_version,
  coalesce(format_version, 'unknown') as pack_format_version
from manifest;
