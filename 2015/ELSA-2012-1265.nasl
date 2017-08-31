# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1265.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123820");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1265");
script_tag(name: "insight", value: "ELSA-2012-1265 -  libxslt security update - [1.1.26-2.0.2.el6_3.1]- Increment release to avoid ULN conflict with previous release.[1.1.26-2.0.1.el6_3.1]- Added libxslt-oracle-enterprise.patch and replaced doc/redhat.gif in tarball[1.1.26-2.el6_3.1]- fixes CVE-2011-1202 CVE-2011-3970 CVE-2012-2825 CVE-2012-2871 CVE-2012-2870- Fix direct pattern matching bug- Fix popping of vars in xsltCompilerNodePop- Fix bug 602515- Fix generate-id() to not expose object addresses (CVE-2011-1202)- Fix some case of pattern parsing errors (CVE-2011-3970)- Fix a bug in selecting XSLT elements (CVE-2012-2825)- Fix portability to upcoming libxml2-2.9.0- Fix default template processing on namespace nodes (CVE-2012-2871)- Cleanup of the pattern compilation code (CVE-2012-2870)- Hardening of code checking node types in various entry point (CVE-2012-2870)- Hardening of code checking node types in EXSLT (CVE-2012-2870)- Fix system-property with unknown namespace- Xsltproc should return an error code if xinclude fails- Fix a dictionary string usage- Avoid a heap use after free error"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1265");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1265.html");
script_cve_id("CVE-2011-1202","CVE-2011-3970","CVE-2012-2825","CVE-2012-2870","CVE-2012-2871");
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
  if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.17~4.0.1.el5_8.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.17~4.0.1.el5_8.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.17~4.0.1.el5_8.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.26~2.0.2.el6_3.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.26~2.0.2.el6_3.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.26~2.0.2.el6_3.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

