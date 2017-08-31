# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1288.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123814");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:55 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1288");
script_tag(name: "insight", value: "ELSA-2012-1288 -  libxml2 security update - [2.7.6-8.0.1.el6_3.3 ]- Update doc/redhat.gif in tarball- Add libxml2-oracle-enterprise.patch and update logos in tarball[2.7.6-8.el6_3.3]- Change the XPath code to percolate allocation error (CVE-2011-1944)[2.7.6-8.el6_3.2]- Fix an off by one pointer access (CVE-2011-3102)[2.7.6-8.el6_3.1]- Fix a failure to report xmlreader parsing failures- Fix parser local buffers size problems (rhbz#843741)- Fix entities local buffers size problems (rhbz#843741)- Fix an error in previous commit (rhbz#843741)- Do not fetch external parsed entities- Impose a reasonable limit on attribute size (rhbz#843741)- Impose a reasonable limit on comment size (rhbz#843741)- Impose a reasonable limit on PI size (rhbz#843741)- Cleanups and new limit APIs for dictionaries (rhbz#843741)- Introduce some default parser limits (rhbz#843741)- Implement some default limits in the XPath module- Fixup limits parser (rhbz#843741)- Enforce XML_PARSER_EOF state handling through the parser- Avoid quadratic behaviour in some push parsing cases (rhbz#843741)- More avoid quadratic behaviour (rhbz#843741)- Strengthen behaviour of the push parser in problematic situations (rhbz#843741)- More fixups on the push parser behaviour (rhbz#843741)- Fix a segfault on XSD validation on pattern error- Fix an unimplemented part in RNG value validation[2.7.6-8.el6]- remove chunk in patch related to configure.in as it breaks rebuild- Resolves: rhbz#788846[2.7.6-7.el6]- fix previous build to force compilation of randomization code- Resolves: rhbz#788846[2.7.6-6.el6]- adds randomization to hash and dict structures CVE-2012-0841- Resolves: rhbz#788846[2.7.6-5.el6]- Make sure the parser returns when getting a Stop order CVE-2011-3905- Fix an allocation error when copying entities CVE-2011-3919- Resolves: rhbz#771910"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1288");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1288.html");
script_cve_id("CVE-2011-3102","CVE-2012-2807");
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
  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.15.0.1.el5_8.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.15.0.1.el5_8.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.15.0.1.el5_8.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~8.0.1.el6_3.3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.7.6~8.0.1.el6_3.3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.7.6~8.0.1.el6_3.3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.7.6~8.0.1.el6_3.3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

