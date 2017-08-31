# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2184.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.122784");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-25 13:18:51 +0200 (Wed, 25 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2184");
script_tag(name: "insight", value: "ELSA-2015-2184 -  realmd security, bug fix, and enhancement update - [0.16.1-5]- Revert 0.16.1-4- Use samba by default- Resolves: rhbz#1271618[0.16.1-4]- Fix regressions in 0.16.x releases- Resolves: rhbz#1258745- Resolves: rhbz#1258488[0.16.1-3]- Fix regression accepting DNS domain names- Resolves: rhbz#1243771[0.16.1-2]- Fix discarded patch: ipa-packages.patch[0.16.1-1]- Updated to upstream 0.16.1- Resolves: rhbz#1241832- Resolves: rhbz#1230941[0.16.0-1]- Updated to upstream 0.16.0- Resolves: rhbz#1174911- Resolves: rhbz#1142191- Resolves: rhbz#1142148[0.14.6-5]- Don't crash when full_name_format is not in sssd.conf [#1051033] This is a regression from a prior update.[0.14.6-4]- Fix full_name_format printf(3) related failure [#1048087][0.14.6-3]- Mass rebuild 2013-12-27[0.14.6-2]- Start oddjob after joining a domain [#967023][0.14.6-1]- Update to upstream 0.14.6 point release- Set 'kerberos method = system keytab' in smb.conf properly [#997580]- Limit Netbios name to 15 chars when joining AD domain [#1001667][0.14.5-1]- Update to upstream 0.14.5 point release- Fix regression conflicting --unattended and -U as in --user args [#996223]- Pass discovered server address to adcli tool [#996995][0.14.4-1]- Update to upstream 0.14.4 point release- Fix up the [sssd] section in sssd.conf if it's screwed up [#987491]- Add an --unattended argument to realm command line client [#976593]- Clearer 'realm permit' manual page example [#985800][0.14.3-1]- Update to upstream 0.14.3 point release- Populate LoginFormats correctly [#967011]- Documentation clarifications [#985773] [#967565]- Set sssd.conf default_shell per domain [#967569]- Notify in terminal output when installing packages [#984960]- If joined via adcli, delete computer with adcli too [#967008]- If input is not a tty, then read from stdin without getpass()- Configure pam_winbind.conf appropriately [#985819]- Refer to FreeIPA as IPA [#967019]- Support use of kerberos ccache to join when winbind [#985817][0.14.2-3]- Run test suite when building the package- Fix rpmlint errors[0.14.2-2]- Install oddjobd and oddjob-mkhomedir when joining domains [#969441][0.14.2-1]- Update to upstream 0.14.2 version- Discover FreeIPA 3.0 with AD trust correctly [#966148]- Only allow joining one realm by default [#966650]- Enable the oddjobd service after joining a domain [#964971]- Remove sssd.conf allow lists when permitting all [#965760]- Add dependency on authconfig [#964675]- Remove glib-networking dependency now that we no longer use SSL.[0.14.1-1]- Update to upstream 0.14.1 version- Fix crasher/regression using passwords with joins [#961435]- Make second Ctrl-C just quit realm tool [#961325]- Fix critical warning when leaving IPA realm [#961320]- Don't print out journalctl command in obvious situations [#961230]- Document the --all option to 'realm discover' [#961279]- No need to require sssd-tools package [#961254]- Enable services even in install mode [#960887]- Use the AD domain name in sssd.conf directly [#960270]- Fix critical warning when service Release() method [#961385][0.14.0-1]- Work around broken krb5 with empty passwords [#960001]- Add manual page for realmd.conf [#959357]- Update to upstream 0.14.0 version[0.13.91-1]- Fix regression when using one time password [#958667]- Support for permitting logins by group [#887675][0.13.90-1]- Add option to disable package-kit installs [#953852]- Add option to use unqualified names [#953825]- Better discovery of domains [#953153]- Concept of managing parts of the system [#914892]- Fix problems with cache directory [#913457]- Clearly explain when realm cannot be joined [#878018]- Many other upstream enhancements and fixes[0.13.3-2]- Add missing glib-networking dependency, currently used for FreeIPA discovery [#953151][0.13.3-1]- Update for upstream 0.13.3 version- Add dependency on systemd for installing service file[0.13.2-2]- Fix problem with sssd not starting after joining[0.13.2-1]- Update to upstream 0.13.2 version[0.13.1-1]- Update to upstream 0.13.1 version for bug fixes[0.12-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild[0.12-1]- Update to upstream 0.12 version for bug fixes[0.11-1]- Update to upstream 0.11 version[0.10-1]- Update to upstream 0.10 version[0.9-1]- Update to upstream 0.9 version[0.8-2]- Add openldap-devel build requirement[0.8-1]- Update to upstream 0.8 version- Add support for translations[0.7-2]- Build requires gtk-doc[0.7-1]- Update to upstream 0.7 version- Remove files no longer present in upstream version- Put documentation in its own realmd-devel-docs subpackage- Update upstream URLs[0.6-1]- Update to upstream 0.6 version[0.5-2]- Remove missing SssdIpa.service file from the files list. This file will return upstream in 0.6[0.5-1]- Update to upstream 0.5 version[0.4-1]- Update to upstream 0.4 version- Cleanup various rpmlint warnings[0.3-2]- Add doc files- Own directories- Remove obsolete parts of spec file- Remove explicit dependencies- Updated License line to LGPLv2+[0.3]- Build fixes[0.2]- Initial RPM"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2184");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2184.html");
script_cve_id("CVE-2015-2704");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"realmd", rpm:"realmd~0.16.1~5.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"realmd-devel-docs", rpm:"realmd-devel-docs~0.16.1~5.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

