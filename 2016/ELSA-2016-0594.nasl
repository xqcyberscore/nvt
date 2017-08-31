# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0594.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.fi
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.122920");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-04-06 14:32:59 +0300 (Wed, 06 Apr 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0594");
script_tag(name: "insight", value: "ELSA-2016-0594 -  graphite2 security, bug fix, and enhancement update - [1.3.6-1]- Related: rhbz#1309052 CVE-2016-1521 CVE-2016-1522 CVE-2016-1523 CVE-2016-1526[1.3.5-1]- Resolves: rhbz#1309052 CVE-2016-1521 CVE-2016-1522 CVE-2016-1523 CVE-2016-1526[1.2.4-6]- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild[1.2.4-5]- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild[1.2.4-4]- Rebuilt for Fedora 23 Change https://fedoraproject.org/wiki/Changes/Harden_all_packages_with_position-independent_code[1.2.4-3]- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild[1.2.4-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild[1.2.4-1]- New upstream release"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0594");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0594.html");
script_cve_id("CVE-2016-1521","CVE-2016-1522","CVE-2016-1523","CVE-2016-1526");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"graphite2", rpm:"graphite2~1.3.6~1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"graphite2-devel", rpm:"graphite2-devel~1.3.6~1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

