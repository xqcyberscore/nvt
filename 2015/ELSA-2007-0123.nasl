# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0123.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122709");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:51:45 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0123");
script_tag(name: "insight", value: "ELSA-2007-0123 -  Moderate: cups security update - [1.1.22-0.rc1.9.18] - REVERTED these changes: - Applied patch from STR #1301 (bug #195354). - Patch pdftops to understand 'includeifexists', and use that in the pdftops.conf file (bug #188583). - Clear the printer's state_message and state_reasons after successful job completion (bug #187457). - Include dest-cache-v2 patch (bug #175847). - Back-ported CUPS 1.2.x change to fix out of order IPP jobs (bug #171142). - Back-ported large file support (bug #211915). - Back-ported HTTP timing fix for STR #1020 (bug #194025). [1.1.22-0.rc1.9.16] - Restored use_dbus setting. [1.1.22-0.rc1.9.15] - Added timeouts to SSL negotiation (bug #232241). [1.1.22-0.rc1.9.14] - Back-ported HTTP timing fix for STR #1020 (bug #194025). [1.1.22-0.rc1.9.13] - Back-ported large file support (bug #211915). [1.1.22-0.rc1.9.12] - Back-ported CUPS 1.2.x change to fix out of order IPP jobs (bug #171142). - Include dest-cache-v2 patch (bug #175847). - Resolves: rhbz #171142"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0123");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0123.html");
script_cve_id("CVE-2007-0720");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.2.4~11.5.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.2.4~11.5.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.2.4~11.5.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.2.4~11.5.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

