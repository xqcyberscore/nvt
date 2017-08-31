# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2550.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122794");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-12-08 11:03:27 +0200 (Tue, 08 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2550");
script_tag(name: "insight", value: "ELSA-2015-2550 -  libxml2 security update - [2.9.1-6.0.1.el7_1.2]- Update doc/redhat.gif in tarball- Add libxml2-oracle-enterprise.patch and update logos in tarball[2.9.1-6.2]- Fix a series of CVEs (rhbz#1286496)- CVE-2015-7941 Stop parsing on entities boundaries errors- CVE-2015-7941 Cleanup conditional section error handling- CVE-2015-8317 Fail parsing early on if encoding conversion failed- CVE-2015-7942 Another variation of overflow in Conditional sections- CVE-2015-7942 Fix an error in previous Conditional section patch- Fix parsing short unclosed comment uninitialized access- CVE-2015-7498 Avoid processing entities after encoding conversion failures- CVE-2015-7497 Avoid an heap buffer overflow in xmlDictComputeFastQKey- CVE-2015-5312 Another entity expansion issue- CVE-2015-7499 Add xmlHaltParser() to stop the parser- CVE-2015-7499 Detect incoherency on GROW- CVE-2015-7500 Fix memory access error due to incorrect entities boundaries- CVE-2015-8242 Buffer overead with HTML parser in push mode- CVE-2015-1819 Enforce the reader to run in constant memory[2.9.1-6]- Fix missing entities after CVE-2014-3660 fix- CVE-2014-0191 Do not fetch external parameter entities (rhbz#1195650)- Fix regressions introduced by CVE-2014-0191 patch[2.9.1-5.1]- CVE-2014-3660 denial of service via recursive entity expansion (rhbz#1149087)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2550");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2550.html");
script_cve_id("CVE-2015-5312","CVE-2015-7497","CVE-2015-7498","CVE-2015-7499","CVE-2015-7500","CVE-2015-7941","CVE-2015-7942","CVE-2015-8241","CVE-2015-8242","CVE-2015-8317","CVE-2015-1819");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

