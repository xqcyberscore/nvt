# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1005.nasl 9402 2018-04-09 07:20:26Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122120");
script_version("$Revision: 9402 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:24 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-04-09 09:20:26 +0200 (Mon, 09 Apr 2018) $");
script_name("Oracle Linux Local Check: ELSA-2011-1005");
script_tag(name: "insight", value: "ELSA-2011-1005 -  sysstat security, bug fix, and enhancement update - [7.0.2-11]- Related: #716959 fix cve-2007-3852 - sysstat insecure temporary file usage[7.0.2-10]- Resolves: #716959 fix cve-2007-3852 - sysstat insecure temporary file usage[7.0.2-9]- Related: #622557 sar interrupt count goes backward[7.0.2-8]- Resolves: #694767 iostat doesn't report statistics for shares with long names- Related: #703095 iostat -n - values in output overflows - problem with long device names on i386[7.0.2-7]- Resolves: #706095 iostat -n - values in output overflows[7.0.2-6]- Resolves: #696672 cifsstat resource leak[7.0.2-5]- Resolves: #604637 extraneous newline in iostat report for long device names- Resolves: #630559 'sar -P ALL -f xxxx' does not display activity information- Resolves: #591530 add cifsiostat tool- Resolves: #598794 Enable parametrization of sadc arguments- Resolves: #675058 iostat: bogus value appears when device is unmounted/mounted- Resolves: #622557 sar interrupt count goes backward[7.0.2-4]- Resolves: #454617 Though function write() executed successful, sadc end with an error- Resolves: #468340 The output of sar -I ALL/XALL is wrong in ia64 machine of RHEL5- Resolves: #517490 The 'sar -d ' command outputs invalid data- Resolves: #578929 March sar data was appended to February data- Resolves: #579409 The sysstat's programs such as mpstat shows one extra cpu- Resolves: #484439 iostat -n enhancement not report NFS client stats correctly"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1005");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1005.html");
script_cve_id("CVE-2007-3852");
script_tag(name:"cvss_base", value:"4.4");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"sysstat", rpm:"sysstat~7.0.2~11.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

