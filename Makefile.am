#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README combo.conf $(MANS) $(XMLS) tst-pam_combo

man_MANS = combo.conf.5 pam_combo.8

XMLS = README.xml combo.conf.5.xml pam_combo.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DPAM_COMBO_CONFIG=\"$(SCONFIGDIR)/combo.conf\"
AM_LDFLAGS =  -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_combo.la
pam_combo_la_LIBADD = -L$(top_builddir)/libpam -lpam @LIBNSL@

secureconf_DATA = combo.conf

if ENABLE_REGENERATE_MAN

noinst_DATA = README

README: pam_combo.8.xml combo.conf.5.xml

-include $(top_srcdir)/Make.xml.rules
endif

TESTS = tst-pam_combo
