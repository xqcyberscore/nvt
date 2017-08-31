# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0500.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123697");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:22 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0500");
script_tag(name: "insight", value: "ELSA-2013-0500 -  hplip security, bug fix and enhancement update - [3.12.4-4] - Applied patch to fix CVE-2013-0200, temporary file vulnerability (bug #902163). - Fixed hpijs-marker-supply patch. [3.12.4-3] - Make 'hp-check' check for hpaio set-up correctly (bug #683007). [3.12.4-2] - Added more fixes from Fedora (bug #731900). [3.12.4-1] - Re-based to 3.12.4 with fixes from Fedora (bug #731900). No longer need no-system-tray, openPPD, addgroup, emit-SIGNAL, fab-root-crash, newline, hpaio-segfault, dbus-threads, or cups-web patches. [3.10.9-4] - The hpijs sub-package no longer requires cupsddk-drivers (which no longer exists as a real package), but cups >= 1.4 (bug #829453)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0500");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0500.html");
script_cve_id("CVE-2011-2722","CVE-2013-0200");
script_tag(name:"cvss_base", value:"1.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~3.12.4~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.4~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"hplip-common", rpm:"hplip-common~3.12.4~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.4~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"hplip-libs", rpm:"hplip-libs~3.12.4~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libsane-hpaio", rpm:"libsane-hpaio~3.12.4~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

