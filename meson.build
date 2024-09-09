project('ndpmon', 'c',
        default_options: [
            'buildtype=debugoptimized',
            'c_std=gnu99',
        ],
        version: '2.1.0.99',
        meson_version: '>= 0.61.0',
       )
release_date = '2024-09-04'

cc = meson.get_compiler('c')

vardatadir = get_option('var-datadir')
if vardatadir == ''
    if get_option('prefix') == '/usr'
        vardatadir = '/var/lib'
        mandir = '/usr/share/man/man8'
    else
        vardatadir = '/var/local/lib'
        mandir = '/usr/local/share/man/man8'
    endif
endif

confdir = get_option('confdir')
if confdir == ''
    if get_option('prefix') == '/usr'
        confdir = '/etc'
    else
        confdir = '/usr/local/etc'
    endif
endif
message('confdir: ' + confdir)

if get_option('webinterface')
    webdir = get_option('webdir')
    if webdir == ''
        webdir = '/var/www/ndpmon'
    endif
    add_project_arguments('-D_WEBINTERFACE_', language: 'c')
else
    webdir = '/nonexistent'
endif

if host_machine.system() == 'linux'
    add_project_arguments('-D_LINUX_', language: ['c'])
elif host_machine.system() == 'openbsd'
    add_project_arguments('-D_OPENBSD_', language: ['c'])
elif host_machine.system() in ['freebsd', 'darwin' ]
    add_project_arguments('-D_FREEBSD_')
elif host_machine.system() == 'netbsd'
    add_project_arguments('-D_NETBSD_')
else
    error('Only Linux, macOS, FreeBSD, NetBSD and OpenBSD are supported')
endif

ndpconfig = configuration_data()
ndpconfig.set('prefix', get_option('prefix'))
ndpconfig.set('exec_prefix', '${prefix}')
ndpconfig.set('datadir', join_paths('${prefix}', 'share'))
ndpconfig.set('sbindir', join_paths('${exec_prefix}', 'sbin'))
ndpconfig.set('sysconfdir', confdir)
ndpconfig.set('localstatedir', '${prefix}/var')
ndpconfig.set('CONFDIR', confdir)
ndpconfig.set('MANDIR', mandir)
ndpconfig.set('VARDATADIR', vardatadir)
ndpconfig.set('WEBDIR', webdir)

configure_file(
    input: 'src/ndpmon_defs.h.in',
    output: 'ndpmon_defs.h',
    configuration: ndpconfig,
)

configure_file(
    input: 'install/ndpmon.sh.in',
    output: 'ndpmon.sh',
    configuration: ndpconfig,
)

configure_file(
    input: 'install/config_ndpmon.xml.in',
    output: 'config_ndpmon.xml',
    configuration: ndpconfig,
    install_dir: join_paths(confdir, 'ndpmon')
)

configure_file(
    input: 'install/neighbor_list.xml.in',
    output: 'neighbor_list.xml',
    configuration: ndpconfig,
    install_dir: join_paths(vardatadir, 'ndpmon')
)

configure_file(
    input: 'install/alerts_to_xml.py.in',
    output: 'alerts_to_xml.py',
    configuration: ndpconfig,
    install_dir: join_paths(get_option('prefix'), 'ndpmon')
)

configure_file(
    input: 'install/ndpmon.8.in',
    output: 'ndpmon.8',
    configuration: ndpconfig,
    install_dir: mandir,
)

libbsd_dep = dependency('libbsd-overlay', required: false)
if not cc.has_function('strlcpy', dependencies: libbsd_dep)
    error('strlcpy missing in libc or libbsd')
endif
libxml2_dep = dependency('libxml-2.0', version: '>= 2.9.13')
libxslt_dep = dependency('libxslt', version: '>= 1.1.34')
thread_dep = dependency('threads')
openssl_dep = dependency('OpenSSL', modules: ['OpenSSL::Crypto'])
use_pcap = false
use_lnfq = false

if get_option('lnfq')
    libnfq_dep = dependency('libnetfilter_queue', version: '>= 1.0.5',
                            required: false)
    if not libnfq_dep.found()
        error('lib_netfilter_queue-dev missing')
    endif
    use_lnfq = true
    add_project_arguments('-D_CAPTURE_USE_LNFQ_', language: 'c')
else
    pcap_dep = dependency('pcap', required: true)
    add_project_arguments('-D_CAPTURE_USE_PCAP_', language: 'c')
    use_pcap = true
endif

srcs_core = files([
    'src/ndpmon.c',
    'src/extensions.c',
    'src/core/alerts.c',
    'src/core/events.c',
    'src/core/extinfo.c',
    'src/core/neighbors.c',
    'src/core/parser.c',
    'src/core/print_packet_info.c',
    'src/core/probes.c',
    'src/core/settings.c',
    'src/core/routers.c',
    'src/core/watchers.c',
])

srcs_capture = files([
    'src/core/capture.c',
    'src/capture/capture_pcap.c',
    'src/capture/capture_lnfq.c',
])

srcs_watch = files([
    'src/watchers/monitoring.c',
    'src/watchers/monitoring_ra.c',
    'src/watchers/monitoring_na.c',
    'src/watchers/monitoring_ns.c',
    'src/watchers/monitoring_rd.c',
])

srcs_plugin_mac_resolv = files([
    'src/plugins/mac_resolv/mac_resolv.c',
])

srcs_plugin_countermeasures = files([
    'src/plugins/countermeasures/icmp_lib.c',
    'src/plugins/countermeasures/icmp_lib_nd.c',
    'src/plugins/countermeasures/countermeasures.c',
])

srcs_plugin_webinterface = files([
    'src/plugins/webinterface/webinterface.c',
])

srcs_plugin_rules = files([
    'src/plugins/rules/rules_matches.c',
    'src/plugins/rules/rules.c',
])

srcs_plugin_soap = files([
    'src/plugins/soap/soap.c',
])

srcs_ndpmon = [
    srcs_core,
    srcs_capture,
    srcs_watch,
]

plugins = [ 'mac_resolv', 'countermeasures', 'webinterface', 'rules', ]

# depends on libcsoap and nanohttp that aren't available anymore ?
# plugins += 'soap'

foreach plugin: plugins
    if get_option(plugin)
        srcs_ndpmon += get_variable('srcs_plugin_' + plugin)
    endif
endforeach

ndpmon_deps = [
    libxml2_dep,
    libxslt_dep,
    openssl_dep,
    libbsd_dep,
]

if use_pcap
    ndpmon_deps += pcap_dep
endif
if use_lnfq
    ndpmon_deps += libnfq_dep
endif

executable('ndpmon',
           srcs_ndpmon,
           dependencies: ndpmon_deps,
           install: true,
           install_dir: join_paths(get_option('prefix'), 'sbin'),
          )

install_data('install/neighbor_list.dtd',
             install_dir: join_paths(vardatadir, 'ndpmon'),
             install_mode: 'rw-r--r--',
            )

install_data('install/config_ndpmon.dtd',
             install_dir: join_paths(confdir, 'ndpmon'),
             install_mode: 'rw-r--r--',
            )
