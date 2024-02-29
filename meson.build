project('aux-scope-example', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3'])

libsystemd = dependency('libsystemd')

executable('aux-scope-example',
           'main.cpp',
           dependencies: libsystemd,
           install : true)

install_data('aux-scope-example.service', install_dir: '/etc/systemd/system/')
