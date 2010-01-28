lib_LTLIBRARIES			= pam_combo.la
pam_combo_la_LDFLAGS		= -avoid-version -module
pam_combo_la_LIBADD		= @LTLIBOBJS@
pam_combo_la_SOURCES		= pam_combo.c
libdir				= @PAMDIR@
man_MANS			= pam_combo.8
AM_CFLAGS			= -Wall  -DPAM_COMBO_CONFIG=\"/etc/security/combo.conf\"

LIBTOOL_DEPS			= @LIBTOOL_DEPS@

secureconfdir = /etc/security
secureconf_DATA = combo.conf


libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
