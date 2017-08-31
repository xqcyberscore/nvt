# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2360.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122745");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:21 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2360");
script_tag(name: "insight", value: "ELSA-2015-2360 -  cups-filters security, bug fix, and enhancement update - [1.0.35-21]- Fix heap-based buffer overflow in texttopdf filter (bug #1241242, CVE-2015-3258, CVE-2015-3279).[1.0.35-20]- Improvements to cups-browsed efficiency patch (bug #1191691).[1.0.35-18]- Fix segfault in texttopdf filter (bug #1194263).- Improve cups-browsed efficiency (bug #1191691).- Fetch printer descriptions with cups-browsed (bug #1223719).- Fix cups-browsed '_' handling for printer names (bug #1167408).[1.0.35-17]- Build against newer poppler (bug #1217552).[1.0.35-16]- Applied upstream patch to fix BrowseAllow parsing issue (CVE-2014-4338, bug #1091568).- Applied upstream patch for cups-browsed DoS via process_browse_data() out-of-bounds read (CVE-2014-4337, bug #1111510)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2360");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2360.html");
script_cve_id("CVE-2015-3258","CVE-2015-3279");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.35~21.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cups-filters-devel", rpm:"cups-filters-devel~1.0.35~21.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cups-filters-libs", rpm:"cups-filters-libs~1.0.35~21.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

