# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0300.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122582");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:48:36 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0300");
script_tag(name: "insight", value: "ELSA-2008-0300 -  bind security, bug fix, and enhancement update - [30:9.3.4-6.P1]- final 5.2 version- minor changes in initscript - improved patches for #250744 and #250901[30:9.3.4-5.P1]- improved patch to handle D-BUS races (#240876)- updated named.root zone to affect root IPv6 migration[30:9.3.4-4.P1]- improved fix for #253537, posttrans script is now used- do not call restorecon on chroot/proc[30:9.3.4-3.P1]- CVE-2008-0122 (small buffer overflow in inet_network)[30:9.3.4-2.P1]- ship /usr/include/dst/gssapi.h file[30:9.3.4-1.P1]- CVE-2007-6283 (#419421)[30:9.3.4-0.9.2.P1]- added GSS-TSIG support to nsupdate (#251528)[30:9.3.4-0.9.1.P1]- updated L.ROOT-SERVERS.NET address in lib/dns/rootns.c file[30:9.3.4-0.9.P1]- fixed building of SDB stuff (#240788)- fixed race condition during DBUS initialization (#240876)- initscript LSD standardization (#242734)[command (#247148)]- fixed wrong perms of named's ldap schema (#250118)- supressed errors from chroot's specfile scripts (#252334)- fixed /dev/random SELinux labelling- added configtest to usage report from named initscript (#250744)- fixed rndc stop return value handler (#250901)- fixed named.log sync in bind-chroot-admin (#247486)- rebased to latest 9.3 maintenance release (9.3.4-P1, #353741)- updated named.root file (new L.ROOT-SERVERS.NET, #363531)- added GSS-TSIG support to named (#251528) - dropped patches (upstream) - bind-9.3.4.P1-query-id.patch - bind-9.3.3rc2-dbus-0.6.patch - bind-9.3.4-validator.patch - bind-9.3.4-nqueries.patch - updated patches - bind-9.3.2-tmpfile.patch"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0300");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0300.html");
script_cve_id("CVE-2007-6283","CVE-2008-0122");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.4~6.P1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

