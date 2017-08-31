# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1606.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123289");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:48 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1606");
script_tag(name: "insight", value: "ELSA-2014-1606 -  file security and bug fix update - [5.04-21]- fix typographical error in changelog[5.04-20]- fix #1037279 - better patch for the bug from previous release[5.04-19]- fix #1037279 - display 'from' field on 32bit ppc core[5.04-18]- fix #664513 - trim white-spaces during ISO9660 detection[5.04-17]- fix CVE-2014-3479 (cdf_check_stream_offset boundary check)- fix CVE-2014-3480 (cdf_count_chain insufficient boundary check)- fix CVE-2014-0237 (cdf_unpack_summary_info() excessive looping DoS)- fix CVE-2014-0238 (CDF property info parsing nelements infinite loop)- fix CVE-2014-2270 (out-of-bounds access in search rules with offsets)- fix CVE-2014-1943 (unrestricted recursion in handling of indirect type rules)- fix CVE-2012-1571 (out of bounds read in CDF parser)[5.04-16]- fix #873997 - improve Minix detection pattern to fix false positives- fix #884396 - improve PBM pattern to fix misdetection with x86 boot sector- fix #980941 - improve Bio-Rad pattern to fix false positives- fix #849621 - tweak strength of XML, Latex and Python patterns to execute them in the proper order- fix #1067771 - detect qcow version 3 images- fix #1064463 - treat RRDTool files as binary files"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1606");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1606.html");
script_cve_id("CVE-2014-0237","CVE-2014-0238","CVE-2014-3479","CVE-2014-3480","CVE-2012-1571","CVE-2014-1943","CVE-2014-2270");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"file", rpm:"file~5.04~21.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"file-devel", rpm:"file-devel~5.04~21.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.04~21.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"file-static", rpm:"file-static~5.04~21.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.04~21.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

