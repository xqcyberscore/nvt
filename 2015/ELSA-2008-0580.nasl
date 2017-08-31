# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0580.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122541");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:47:36 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0580");
script_tag(name: "insight", value: "ELSA-2008-0580 -  vim security update - [7.0.109-4.4z]- fix netrw[7.0.109-4.3z]- fixes CVE-2008-3074 (tar plugin)- fixes CVE-2008-3075 (zip plugin)- fixes CVE-2008-3076 (netrw plugin)- fixes CVE-2008-4101 (keyword and tag lookup)[7.0.109-4.2z]- fix some issues with netrw and remote file editing caused by the CVE-2008-2712 patch[7.0.109-4.1z]- more fixes for CVE-2008-2712[7.0.109-4.z]- fix release[7.0.109-3.1z]- rebuild for z stream[7.0.109-3.6]- re-enable debuginfo[7.0.109-3.5]- update netrw files for CVE-2008-2712[7.0.109-3.4]- add fixes for CVE-2007-2953 and CVE-2008-2712"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0580");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0580.html");
script_cve_id("CVE-2007-2953","CVE-2008-2712","CVE-2008-3074","CVE-2008-3075","CVE-2008-4101","CVE-2008-6235");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.0.109~4.el5_2.4z", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.0.109~4.el5_2.4z", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.0.109~4.el5_2.4z", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.0.109~4.el5_2.4z", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

