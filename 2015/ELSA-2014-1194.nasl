# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1194.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123308");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:04 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1194");
script_tag(name: "insight", value: "ELSA-2014-1194 -  conga security and bug fix update - [0.12.2-81.0.2.el5]- Replaced redhat logo image in Data.fs[0.12.2-81.0.1.el5]- Added conga-enterprise-Carthage.patch to support OEL5- Replaced redhat logo image in conga-0.12.2.tar.gz[0.12.2-81]- luci: prevent non-admin user from unauthorized executive access Resolves: rhbz#1089310[0.12.2-79]- luci: drop unsuccessful monkey patch application wrt. Plone 20121106 advisory Related: rhbz#956861[0.12.2-78]- luci: reflect startup_wait parameter added in postgres-8 RA Resolves: rhbz#1065263- luci: Multiple information leak flaws in various luci site extensions Resolves: rhbz#1076148[0.12.2-72]- luci: fix mishandling of distro release string Resolves: rhbz#1072075- luci: fix initscript does not check return values correctly Resolves: rhbz#970288- ricci: fix end-use modules do not handle stdin polling correctly Resolves: rhbz#1076711[0.12.2-69]- luci: apply relevant parts of Plone 20121106 advisory (multiple vectors) Resolves: rhbz#956861"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1194");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1194.html");
script_cve_id("CVE-2012-5498","CVE-2012-5499","CVE-2012-5500","CVE-2013-6496","CVE-2014-3521","CVE-2012-5485","CVE-2012-5486","CVE-2012-5488","CVE-2012-5497");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"luci", rpm:"luci~0.12.2~81.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.12.2~81.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

