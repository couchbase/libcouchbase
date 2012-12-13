# This file contains the rules used to build the manual pages
# with asciidoc

A2XFLAGS=-L --doctype manpage --format manpage

GENERATED_MANPAGES = \
   man/man3couchbase/lcb_arithmetic.3couchbase \
   man/man3couchbase/lcb_behavior_get_config_errors_threshold.3couchbase \
   man/man3couchbase/lcb_behavior_get_ipv6.3couchbase \
   man/man3couchbase/lcb_behavior_get_syncmode.3couchbase \
   man/man3couchbase/lcb_connect.3couchbase \
   man/man3couchbase/lcb_create.3couchbase \
   man/man3couchbase/lcb_create_compat.3couchbase \
   man/man3couchbase/lcb_create_io_ops.3couchbase \
   man/man3couchbase/lcb_destroy.3couchbase \
   man/man3couchbase/lcb_destroy_io_ops.3couchbase \
   man/man3couchbase/lcb_enable_timings.3couchbase \
   man/man3couchbase/lcb_flush.3couchbase \
   man/man3couchbase/lcb_flush_buffers.3couchbase \
   man/man3couchbase/lcb_get.3couchbase \
   man/man3couchbase/lcb_get_cookie.3couchbase \
   man/man3couchbase/lcb_get_host.3couchbase \
   man/man3couchbase/lcb_get_last_error.3couchbase \
   man/man3couchbase/lcb_get_num_nodes.3couchbase \
   man/man3couchbase/lcb_get_num_replicas.3couchbase \
   man/man3couchbase/lcb_get_replica.3couchbase \
   man/man3couchbase/lcb_get_server_list.3couchbase \
   man/man3couchbase/lcb_get_timeout.3couchbase \
   man/man3couchbase/lcb_get_version.3couchbase \
   man/man3couchbase/lcb_make_http_request.3couchbase \
   man/man3couchbase/lcb_observe.3couchbase \
   man/man3couchbase/lcb_remove.3couchbase \
   man/man3couchbase/lcb_server_stats.3couchbase \
   man/man3couchbase/lcb_server_versions.3couchbase \
   man/man3couchbase/lcb_set_arithmetic_callback.3couchbase \
   man/man3couchbase/lcb_set_configuration_callback.3couchbase \
   man/man3couchbase/lcb_set_error_callback.3couchbase \
   man/man3couchbase/lcb_set_flush_callback.3couchbase \
   man/man3couchbase/lcb_set_get_callback.3couchbase \
   man/man3couchbase/lcb_set_http_complete_callback.3couchbase \
   man/man3couchbase/lcb_set_http_data_callback.3couchbase \
   man/man3couchbase/lcb_set_observe_callback.3couchbase \
   man/man3couchbase/lcb_set_remove_callback.3couchbase \
   man/man3couchbase/lcb_set_stat_callback.3couchbase \
   man/man3couchbase/lcb_set_store_callback.3couchbase \
   man/man3couchbase/lcb_set_touch_callback.3couchbase \
   man/man3couchbase/lcb_set_unlock_callback.3couchbase \
   man/man3couchbase/lcb_set_verbosity.3couchbase \
   man/man3couchbase/lcb_set_verbosity_callback.3couchbase \
   man/man3couchbase/lcb_set_version_callback.3couchbase \
   man/man3couchbase/lcb_store.3couchbase \
   man/man3couchbase/lcb_strerror.3couchbase \
   man/man3couchbase/lcb_timer_create.3couchbase \
   man/man3couchbase/lcb_touch.3couchbase \
   man/man3couchbase/lcb_unlock.3couchbase \
   man/man3couchbase/lcb_verify_struct_size.3couchbase \
   man/man3couchbase/lcb_wait.3couchbase \
   man/man3lib/libcouchbase.3lib \
   man/man5/lcb_attributes.5

ALL_MANPAGES = \
   man/man3couchbase/lcb_behavior_set_config_errors_threshold.3couchbase \
   man/man3couchbase/lcb_behavior_set_ipv6.3couchbase \
   man/man3couchbase/lcb_behavior_set_syncmode.3couchbase \
   man/man3couchbase/lcb_breakout.3couchbase \
   man/man3couchbase/lcb_cancel_http_request.3couchbase \
   man/man3couchbase/lcb_disable_timings.3couchbase \
   man/man3couchbase/lcb_get_port.3couchbase \
   man/man3couchbase/lcb_get_timings.3couchbase \
   man/man3couchbase/lcb_is_waiting.3couchbase \
   man/man3couchbase/lcb_set_cookie.3couchbase \
   man/man3couchbase/lcb_set_timeout.3couchbase \
   man/man3couchbase/lcb_timer_destroy.3couchbase \
   man/man3couchbase/lcb_verify_compiler_setup.3couchbase \
   $(GENERATED_MANPAGES)

if HAVE_A2X

BUILT_SOURCES += ${ALL_MANPAGES}
CLEANFILES += $(GENERATED_MANPAGES)

if MANPAGE_BSD_LAYOUT

BUILT_SOURCES += man/generated_bsd_pages

rewrite_MANS = man/man3/lcb_arithmetic.3 \
   man/man3/lcb_behavior_get_config_errors_threshold.3 \
   man/man3/lcb_behavior_get_ipv6.3 \
   man/man3/lcb_behavior_get_syncmode.3 \
   man/man3/lcb_behavior_set_config_errors_threshold.3 \
   man/man3/lcb_behavior_set_ipv6.3 \
   man/man3/lcb_behavior_set_syncmode.3 \
   man/man3/lcb_breakout.3 \
   man/man3/lcb_cancel_http_request.3 \
   man/man3/lcb_connect.3 \
   man/man3/lcb_create.3 \
   man/man3/lcb_create_compat.3 \
   man/man3/lcb_create_io_ops.3 \
   man/man3/lcb_destroy.3 \
   man/man3/lcb_destroy_io_ops.3 \
   man/man3/lcb_disable_timings.3 \
   man/man3/lcb_enable_timings.3 \
   man/man3/lcb_flush.3 \
   man/man3/lcb_flush_buffers.3 \
   man/man3/lcb_get.3 \
   man/man3/lcb_get_cookie.3 \
   man/man3/lcb_get_host.3 \
   man/man3/lcb_get_last_error.3 \
   man/man3/lcb_get_num_nodes.3 \
   man/man3/lcb_get_num_replicas.3 \
   man/man3/lcb_get_port.3 \
   man/man3/lcb_get_replica.3 \
   man/man3/lcb_get_server_list.3 \
   man/man3/lcb_get_timeout.3 \
   man/man3/lcb_get_timings.3 \
   man/man3/lcb_get_version.3 \
   man/man3/lcb_is_waiting.3 \
   man/man3/lcb_make_http_request.3 \
   man/man3/lcb_observe.3 \
   man/man3/lcb_remove.3 \
   man/man3/lcb_server_stats.3 \
   man/man3/lcb_server_versions.3 \
   man/man3/lcb_set_arithmetic_callback.3 \
   man/man3/lcb_set_configuration_callback.3 \
   man/man3/lcb_set_cookie.3 \
   man/man3/lcb_set_error_callback.3 \
   man/man3/lcb_set_flush_callback.3 \
   man/man3/lcb_set_get_callback.3 \
   man/man3/lcb_set_http_complete_callback.3 \
   man/man3/lcb_set_http_data_callback.3 \
   man/man3/lcb_set_observe_callback.3 \
   man/man3/lcb_set_remove_callback.3 \
   man/man3/lcb_set_stat_callback.3 \
   man/man3/lcb_set_store_callback.3 \
   man/man3/lcb_set_timeout.3 \
   man/man3/lcb_set_touch_callback.3 \
   man/man3/lcb_set_unlock_callback.3 \
   man/man3/lcb_set_verbosity.3 \
   man/man3/lcb_set_verbosity_callback.3 \
   man/man3/lcb_set_version_callback.3 \
   man/man3/lcb_store.3 \
   man/man3/lcb_strerror.3 \
   man/man3/lcb_timer_create.3 \
   man/man3/lcb_timer_destroy.3 \
   man/man3/lcb_touch.3 \
   man/man3/lcb_unlock.3 \
   man/man3/lcb_verify_struct_size.3 \
   man/man3/lcb_verify_compiler_setup.3 \
   man/man3/lcb_wait.3 \
   man/man3/libcouchbase.3 \
   man/man5/lcb_attributes.5

CLEANFILES += $(rewrite_MANS)
man_MANS += $(rewrite_MANS)

else

man_MANS += ${ALL_MANPAGES}

endif
endif

${builddir}/man/man3lib:; -@mkdir $@
${builddir}/man/man3couchbase:; -@mkdir $@
${builddir}/man/man3:; -@mkdir $@
${builddir}/man/man5:; -@mkdir $@

SUFFIXES= .3lib .3lib.txt .3couchbase .3couchbase.txt .5 .5.txt

# Generate a man page from section 3lib from the .3lib.txt file
.3lib.txt.3lib:
	@mkdir -p ${builddir}/man/man3lib
	$(A2X) $(A2XFLAGS) -D ${builddir}/man/man3lib $<

# Generate a man page from section 3couchbase from the .3couchbase.txt file
.3couchbase.txt.3couchbase:
	@mkdir -p ${builddir}/man/man3couchbase
	$(A2X) $(A2XFLAGS) -D ${builddir}/man/man3couchbase $<

.5.txt.5:
	@mkdir -p ${builddir}/man/man5
	$(A2X) $(A2XFLAGS) -D ${builddir}/man/man5 $<

${builddir}/man/generated_bsd_pages: ${ALL_MANPAGES}
	@for file in ${builddir}/man/man3couchbase/*.3couchbase \
                     ${builddir}/man/man3lib/*.3lib \
                     ${srcdir}/man/man3couchbase/*.3couchbase \
           ; do \
	   mkdir -p ${builddir}/man/man3; \
	   sed -e s,3lib,3,g -e s,3couchbase,3,g $$file > ${builddir}/man/man3/`basename $$file | sed -e s,3couchbase,3,g -e s,3lib,3,g`; \
        done
