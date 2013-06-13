Name:           pam_combo
Version:        0.2
Release:        4%{?dist}
Summary:        A Pluggable Authentication Module combining access and time

Group:          System Environment/Base
License:        BSD and GPLv2+
Source0:	pam_combo-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: pam-devel
BuildRequires: autoconf >= 2.60
BuildRequires: automake, libtool

%define _sbindir /sbin
%define _moduledir /%{_lib}/security
%define _secconfdir %{_sysconfdir}/security
%define _pamconfdir %{_sysconfdir}/pam.d


%description
This is pam_combo, a pluggable authentication module that combines
pam_access with pam_time.

%prep
%setup -q

libtoolize -f
autoreconf --install

%build
%configure --libdir=/%{_lib} \
           --with-pam-dir=/%{_lib}/security/
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm $RPM_BUILD_ROOT/%{_lib}/security/pam_combo.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc NEWS README COPYING ChangeLog
/%{_lib}/security/pam_combo.so
%{_mandir}/man8/*
%{_mandir}/man5/*
%dir %{_secconfdir}
%config(noreplace) %{_secconfdir}/combo.conf

%changelog

* Tue Apr 30 2013 Bill Pemberton <wfp5p@virginia.edu> - 0.2-3
- fix spelling in summary
