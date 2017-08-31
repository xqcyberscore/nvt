# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0134.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131312");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-05-09 14:18:14 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0134");
script_tag(name: "insight", value: "Adobe Flash Player 11.2.202.616 contains fixes to critical security vulnerabilities found in earlier versions that could potentially allow an attacker to take control of the affected system. This update hardens a mitigation against JIT spraying attacks that could be used to bypass memory layout randomization mitigations (CVE-2016-1006). This update resolves type confusion vulnerabilities that could lead to code execution (CVE-2016-1015, CVE-2016-1019). This update resolves use-after-free vulnerabilities that could lead to code execution (CVE-2016-1011, CVE-2016-1013, CVE-2016-1016, CVE-2016-1017, CVE-2016-1031). This update resolves memory corruption vulnerabilities that could lead to code execution (CVE-2016-1012, CVE-2016-1020, CVE-2016-1021, CVE-2016-1022, CVE-2016-1023, CVE-2016-1024, CVE-2016-1025, CVE-2016-1026, CVE-2016-1027, CVE-2016-1028, CVE-2016-1029, CVE-2016-1032, CVE-2016-1033). This update resolves a stack overflow vulnerability that could lead to code execution (CVE-2016-1018). This update resolves a security bypass vulnerability (CVE-2016-1030). This update resolves a vulnerability in the directory search path used to find resources that could lead to code execution (CVE-2016-1014). Adobe reports that CVE-2016-1019 is already being actively exploited on Windows systems."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0134.html");
script_cve_id("CVE-2016-1006","CVE-2016-1011","CVE-2016-1012","CVE-2016-1013","CVE-2016-1014","CVE-2016-1015","CVE-2016-1016","CVE-2016-1017","CVE-2016-1018","CVE-2016-1019","CVE-2016-1020","CVE-2016-1021","CVE-2016-1022","CVE-2016-1023","CVE-2016-1024","CVE-2016-1025","CVE-2016-1026","CVE-2016-1027","CVE-2016-1028","CVE-2016-1029","CVE-2016-1030","CVE-2016-1031","CVE-2016-1032","CVE-2016-1033");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0134");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.616~1.mga5.nonfree", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
