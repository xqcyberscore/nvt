# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1701.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123520");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1701");
script_tag(name: "insight", value: "ELSA-2013-1701 -  sudo security, bug fix and enhancement update - [1.8.6p3-12] - added patches for CVE-2013-1775 CVE-2013-2777 CVE-2013-2776 Resolves: rhbz#1015355 [1.8.6p3-11] - sssd: fixed a bug in ipa_hostname processing Resolves: rhbz#853542 [1.8.6p3-10] - sssd: fixed buffer size for the ipa_hostname value Resolves: rhbz#853542 [1.8.6p3-9] - sssd: match against ipa_hostname from sssd.conf too when checking sudoHost Resolves: rhbz#853542 [1.8.6p3-8] - updated man-page - fixed handling of RLIMIT_NPROC resource limit - fixed alias cycle detection code - added debug messages for tracing of netgroup matching - fixed aborting on realloc when displaying allowed commands - show the SUDO_USER in logs, if running commands as root - sssd: filter netgroups in the sudoUser attribute Resolves: rhbz#856901 Resolves: rhbz#947276 Resolves: rhbz#886648 Resolves: rhbz#994563 Resolves: rhbz#848111 Resolves: rhbz#994626 Resolves: rhbz#973228 Resolves: rhbz#880150"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1701");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1701.html");
script_cve_id("CVE-2013-1775","CVE-2013-2776","CVE-2013-2777");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~12.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.6p3~12.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

