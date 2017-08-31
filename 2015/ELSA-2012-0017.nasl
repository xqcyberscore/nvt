# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0017.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122013");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:41 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0017");
script_tag(name: "insight", value: "ELSA-2012-0017 -  libxml2 security update - [2.6.26-2.1.12.0.1.el5_7.2]- Add libxml2-enterprise.patch- Replaced docs/redhat.gif in tarball with updated image[2.6.26-2.1.12.el5_7.2]- Fix the semantic of XPath axis for namespace/attribute nodes CVE-2010-4008- Fix an off by one error in encoding CVE-2011-0216- Fix some potential problems on reallocation failures CVE-2011-1944- Fix missing error status in XPath evaluation CVE-2011-2834- Make sure the parser returns when getting a Stop order CVE-2011-3905- Fix an allocation error when copying entities CVE-2011-3919.patch- Resolves: rhbz#771906"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0017");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0017.html");
script_cve_id("CVE-2010-4008","CVE-2011-0216","CVE-2011-1944","CVE-2011-2834","CVE-2011-3905","CVE-2011-3919");
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
  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.12.0.1.el5_7.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.12.0.1.el5_7.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.12.0.1.el5_7.2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

