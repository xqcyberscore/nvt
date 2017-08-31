# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0468.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131148");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-12-10 11:05:50 +0200 (Thu, 10 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0468");
script_tag(name: "insight", value: "Adobe Flash Player 11.2.202.554 contains fixes to critical security vulnerabilities found in earlier versions that could potentially allow an attacker to take control of the affected system. This update resolves heap buffer overflow vulnerabilities that could lead to code execution (CVE-2015-8438, CVE-2015-8446). This update resolves memory corruption vulnerabilities that could lead to code execution (CVE-2015-8444, CVE-2015-8443, CVE-2015-8417, CVE-2015-8416, CVE-2015-8451, CVE-2015-8047, CVE-2015-8053, CVE-2015-8045, CVE-2015-8051, CVE-2015-8060, CVE-2015-8419, CVE-2015-8408). This update resolves security bypass vulnerabilities (CVE-2015-8453, CVE-2015-8440, CVE-2015-8409). This update resolves a stack overflow vulnerability that could lead to code execution (CVE-2015-8407). This update resolves a type confusion vulnerability that could lead to code execution (CVE-2015-8439). This update resolves an integer overflow vulnerability that could lead to code execution (CVE-2015-8445). This update resolves a buffer overflow vulnerability that could lead to code execution (CVE-2015-8415) This update resolves use-after-free vulnerabilities that could lead to code execution (CVE-2015-8050, CVE-2015-8049, CVE-2015-8437, CVE-2015-8450, CVE-2015-8449, CVE-2015-8448, CVE-2015-8436, CVE-2015-8452, CVE-2015-8048, CVE-2015-8413, CVE-2015-8412, CVE-2015-8410, CVE-2015-8411, CVE-2015-8424, CVE-2015-8422, CVE-2015-8420, CVE-2015-8421, CVE-2015-8423, CVE-2015-8425, CVE-2015-8433, CVE-2015-8432, CVE-2015-8431, CVE-2015-8426, CVE-2015-8430, CVE-2015-8427, CVE-2015-8428, CVE-2015-8429, CVE-2015-8434, CVE-2015-8435, CVE-2015-8414, CVE-2015-8052, CVE-2015-8059, CVE-2015-8058, CVE-2015-8055, CVE-2015-8057, CVE-2015-8056, CVE-2015-8061, CVE-2015-8067, CVE-2015-8066, CVE-2015-8062, CVE-2015-8068, CVE-2015-8064, CVE-2015-8065, CVE-2015-8063, CVE-2015-8405, CVE-2015-8404, CVE-2015-8402, CVE-2015-8403, CVE-2015-8071, CVE-2015-8401, CVE-2015-8406, CVE-2015-8069, CVE-2015-8070, CVE-2015-8441, CVE-2015-8442, CVE-2015-8447)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0468.html");
script_cve_id("CVE-2015-8045","CVE-2015-8047","CVE-2015-8048","CVE-2015-8049","CVE-2015-8050","CVE-2015-8051","CVE-2015-8052","CVE-2015-8053","CVE-2015-8054","CVE-2015-8055","CVE-2015-8056","CVE-2015-8057","CVE-2015-8058","CVE-2015-8059","CVE-2015-8060","CVE-2015-8061","CVE-2015-8062","CVE-2015-8063","CVE-2015-8064","CVE-2015-8065","CVE-2015-8066","CVE-2015-8067","CVE-2015-8068","CVE-2015-8069","CVE-2015-8070","CVE-2015-8071","CVE-2015-8401","CVE-2015-8402","CVE-2015-8403","CVE-2015-8404","CVE-2015-8405","CVE-2015-8406","CVE-2015-8407","CVE-2015-8408","CVE-2015-8409","CVE-2015-8410","CVE-2015-8411","CVE-2015-8412","CVE-2015-8413","CVE-2015-8414","CVE-2015-8415","CVE-2015-8416","CVE-2015-8417","CVE-2015-8419","CVE-2015-8420","CVE-2015-8421","CVE-2015-8422","CVE-2015-8423","CVE-2015-8424","CVE-2015-8425","CVE-2015-8426","CVE-2015-8427","CVE-2015-8428","CVE-2015-8429","CVE-2015-8430","CVE-2015-8431","CVE-2015-8432","CVE-2015-8433","CVE-2015-8434","CVE-2015-8435","CVE-2015-8436","CVE-2015-8437","CVE-2015-8438","CVE-2015-8439","CVE-2015-8440","CVE-2015-8441","CVE-2015-8442","CVE-2015-8443","CVE-2015-8444","CVE-2015-8445","CVE-2015-8446","CVE-2015-8447","CVE-2015-8448","CVE-2015-8449","CVE-2015-8450","CVE-2015-8451","CVE-2015-8452","CVE-2015-8453");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0468");
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
if ((res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.554~1.mga5.nonfree", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
