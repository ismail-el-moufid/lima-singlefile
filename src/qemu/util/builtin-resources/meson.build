# The generated blob is a source-tree input, never a runtime firmware file.
builtin_path = configuration_data()
builtin_path.set_quoted('QEMU_BUILTIN_DATA_FILE',
                       meson.current_source_dir() / 'builtin-data.bin')
builtin_path_h = configure_file(output: 'builtin-path.h',
                                configuration: builtin_path)
# Meson cannot discover .incbin dependencies; changing the blob must rebuild .S.
builtin_asm = custom_target('builtin-data-asm',
  input: files('builtin-data.bin', 'builtin-data.S'),
  output: 'builtin-data-generated.S',
  command: [find_program('cp'), '@INPUT1@', '@OUTPUT@'])
builtin_dep = declare_dependency(
  include_directories: include_directories('.'),
  sources: builtin_path_h)
util_ss.add(files('registry.c'), builtin_asm, builtin_dep)
