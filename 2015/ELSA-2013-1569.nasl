# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1569.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123521");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1569");
script_tag(name: "insight", value: "ELSA-2013-1569 -  wireshark security, bug fix, and enhancement update - [1.8.10-4.0.1.el6] - Add oracle-ocfs2-network.patch to allow disassembly of OCFS2 interconnect [1.8.10-4] - fix memory leak when reassemblying a packet - Related: #711024 [1.8.10-3] - fix config.h conflict - Related: #711024 [1.8.10-2] - do not configure with setcap-install - Related: #711024 [1.8.10-1] - upgrade to 1.8.10 - see http://www.wireshark.org/docs/relnotes/wireshark-1.8.10.html - Related: #711024 [1.8.8-10] - fix consolehelper path for dumpcap - Related: #711024 [1.8.8-9] - fix dumpcap group - Related: #711024 [1.8.8-8] - fix tshark output streams and formatting for -L, -D - Resolves: #1004636 [1.8.8-7] - fix double free in wiretap/netmon.c - Related: #711024 [1.8.8-6] - security patches - Resolves: CVE-2013-4927 CVE-2013-4931 CVE-2013-4932 CVE-2013-4933 CVE-2013-4934 CVE-2013-4935 CVE-2013-3557 [1.8.8-5] - fix desktop file - Related: #711024 [1.8.8-4] - fix tap-iostat buffer overflow - fix dcom string overrun - fix sctp bytes graph crash - fix airpcap dialog crash - Related: #711024 [1.8.8-3] - fix dumpcap privileges to 755 - Related: #711024 [1.8.8-2] - new sources - Related: #711024 [1.8.8-1] - upgrade to 1.8.8 - see http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html - Resolves: #711024 - Resolves: #858976 - Resolves: #699636 - Resolves: #750712 - Resolves: #832021 - Resolves: #889346 - Resolves: #659661 - Resolves: #715560 [1.2.15-3] - security patches - Resolves: CVE-2011-1143 CVE-2011-1590 CVE-2011-1957 CVE-2011-1959 CVE-2011-2174 CVE-2011-2175 CVE-2011-1958 CVE-2011-2597 CVE-2011-2698 CVE-2011-4102 CVE-2012-0041 CVE-2012-0066 CVE-2012-0067 CVE-2012-0042 CVE-2012-1595"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1569");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1569.html");
script_cve_id("CVE-2012-4285","CVE-2012-4289","CVE-2012-4290","CVE-2012-4291","CVE-2012-2392","CVE-2012-3825","CVE-2012-4288","CVE-2012-4292","CVE-2012-5595","CVE-2012-5597","CVE-2012-5598","CVE-2012-5599","CVE-2012-5600","CVE-2012-6056","CVE-2012-6059","CVE-2012-6060","CVE-2012-6061","CVE-2012-6062","CVE-2013-3557","CVE-2013-3559","CVE-2013-3561","CVE-2013-4081","CVE-2013-4083","CVE-2013-4927","CVE-2013-4931","CVE-2013-4932","CVE-2013-4933","CVE-2013-4934","CVE-2013-4935","CVE-2013-4936","CVE-2013-5721");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~4.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.8.10~4.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.8.10~4.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

