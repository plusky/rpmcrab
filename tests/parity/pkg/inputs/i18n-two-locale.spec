Name:           i18n-two-locale
Version:        1.0
Release:        1
Summary:        Two-locale i18n fixture
Summary(de):    Zweisprachiges i18n-Testpaket
License:        MIT
BuildArch:      noarch

%description
Fixture for Pkg::tag_i18n_str (follow-up to #248): a real RPM whose header
carries SUMMARY and DESCRIPTION in two locales, so HEADERI18NTABLE has two
entries. Covers the lang != "C" branch and the i18n-table index mapping over
a real package header instead of a synthetic inline case.

%description -l de
Testpaket fuer Pkg::tag_i18n_str: SUMMARY und DESCRIPTION in zwei Sprachen
(C und de), damit HEADERI18NTABLE zwei Eintraege hat.

%install
mkdir -p %{buildroot}/usr/share/doc/i18n-two-locale
echo fixture > %{buildroot}/usr/share/doc/i18n-two-locale/README

%files
%defattr(-,root,root,-)
/usr/share/doc/i18n-two-locale/README

%changelog
* Tue Oct 06 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Two-locale i18n fixture for Pkg::tag_i18n_str (follow-up to #248).
