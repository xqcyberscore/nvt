# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0581.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123687");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:14 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0581");
script_tag(name: "insight", value: "ELSA-2013-0581 -  libxml2 security update - [2.7.6-12.0.1.el6_4.1]- Update doc/redhat.gif in tarball- Add libxml2-oracle-enterprise.patch and update logos in tarball[2.7.6-12.el6_4.1]-detect and stop excessive entities expansion upon replacement (rhbz#912574)[2.7.6-12.el6]- fix out of range heap access (CVE-2012-5134)[2.7.6-11.el6]- Change the XPath code to percolate allocation error (CVE-2011-1944)[2.7.6-10.el6]- Fix an off by one pointer access (CVE-2011-3102)[2.7.6-9.el6]- Fix a failure to report xmlreader parsing failures- Fix parser local buffers size problems (rhbz#843742)- Fix entities local buffers size problems (rhbz#843742)- Fix an error in previous commit (rhbz#843742)- Do not fetch external parsed entities- Impose a reasonable limit on attribute size (rhbz#843742)- Impose a reasonable limit on comment size (rhbz#843742)- Impose a reasonable limit on PI size (rhbz#843742)- Cleanups and new limit APIs for dictionaries (rhbz#843742)- Introduce some default parser limits (rhbz#843742)- Implement some default limits in the XPath module- Fixup limits parser (rhbz#843742)- Enforce XML_PARSER_EOF state handling through the parser- Avoid quadratic behaviour in some push parsing cases (rhbz#843742)- More avoid quadratic behaviour (rhbz#843742)- Strengthen behaviour of the push parser in problematic situations (rhbz#843742)- More fixups on the push parser behaviour (rhbz#843742)- Fix a segfault on XSD validation on pattern error- Fix an unimplemented part in RNG value validation"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0581");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0581.html");
script_cve_id("CVE-2013-0338");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.21.0.1.el5_9.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.21.0.1.el5_9.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.21.0.1.el5_9.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

