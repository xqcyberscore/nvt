# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0979.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122651");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:50:18 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0979");
script_tag(name: "insight", value: "ELSA-2007-0979 -  Critical: firefox security update - [1.5.0.12-0.7.el4.0.1] - Add firefox-oracle-default-bookmarks.html and firefox-oracle-default-prefs.js for errata rebuild [1.5.0.12-0.7.el4] - Update to latest snapshot of Mozilla 1.8.0 branch [1.5.0.12-0.6.el4] - added pathes for Mozilla bugs 325761 and 392149 [1.5.0.12-0.5.el4] - added pathes for Mozilla bugs 199088,267833,309322,345305,361745, 362901,372309,378787,381300,384105,386914,387033,387881,388121,388784 390078,393537,395942 [1.5.0.12-0.4.el4] - Updated pango patches, added indic printing support (#129207)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0979");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0979.html");
script_cve_id("CVE-2007-1095","CVE-2007-2292","CVE-2007-3511","CVE-2007-3844","CVE-2007-5334","CVE-2007-5337","CVE-2007-5338","CVE-2007-5339","CVE-2007-5340");
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
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~1.5.0.12~6.el5.0.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~1.5.0.12~6.el5.0.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

