# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0379.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.130012");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:30 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0379");
script_tag(name: "insight", value: "Adobe Flash Player 11.2.202.521 contains fixes to critical security vulnerabilities found in earlier versions that could potentially allow an attacker to take control of the affected system. This update resolves a type confusion vulnerability that could lead to code execution (CVE-2015-5573). This update resolves use-after-free vulnerabilities that could lead to code execution (CVE-2015-5570, CVE-2015-5574, CVE-2015-5581, CVE-2015-5584, CVE-2015-6682). This update resolves buffer overflow vulnerabilities that could lead to code execution (CVE-2015-6676, CVE-2015-6678). This update resolves memory corruption vulnerabilities that could lead to code execution (CVE-2015-5575, CVE-2015-5577, CVE-2015-5578, CVE-2015-5580, CVE-2015-5582, CVE-2015-5588, CVE-2015-6677). This update includes additional validation checks to ensure that Flash Player rejects malicious content from vulnerable JSONP callback APIs (CVE-2015-5571). This update resolves a memory leak vulnerability (CVE-2015-5576). This update includes further hardening to a mitigation to defend against vector length corruptions (CVE-2015-5568). This update resolves stack corruption vulnerabilities that could lead to code execution (CVE-2015-5567, CVE-2015-5579). This update resolves a stack overflow vulnerability that could lead to code execution (CVE-2015-5587). This update resolves a security bypass vulnerability that could lead to information disclosure (CVE-2015-5572). This update resolves a vulnerability that could be exploited to bypass the same-origin-policy and lead to information disclosure (CVE-2015-6679)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0379.html");
script_cve_id("CVE-2015-5567","CVE-2015-5568","CVE-2015-5570","CVE-2015-5571","CVE-2015-5572","CVE-2015-5573","CVE-2015-5574","CVE-2015-5575","CVE-2015-5576","CVE-2015-5577","CVE-2015-5578","CVE-2015-5579","CVE-2015-5580","CVE-2015-5581","CVE-2015-5582","CVE-2015-5584","CVE-2015-5587","CVE-2015-5588","CVE-2015-6676","CVE-2015-6677","CVE-2015-6678","CVE-2015-6679","CVE-2015-6682");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0379");
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
if ((res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.521~1.mga5.nonfree", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
