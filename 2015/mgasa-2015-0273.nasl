# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0273.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130105");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:42:45 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0273");
script_tag(name: "insight", value: "Adobe Flash Player 11.2.202.481 contains fixes to critical security vulnerabilities found in earlier versions that could potentially allow an attacker to take control of the affected system. Adobe is aware of a report that an exploit targeting CVE-2015-5119 has been publicly published. This updates resolves heap buffer overflow vulnerabilities that could lead to code execution (CVE-2015-3135, CVE-2015-4432, CVE-2015-5118). This updates resolves memory corruption vulnerabilities that could lead to code execution (CVE-2015-3117, CVE-2015-3123, CVE-2015-3130, CVE-2015-3133, CVE-2015-3134, CVE-2015-4431). This updates resolves null pointer dereference issues (CVE-2015-3126, CVE-2015-4429). This updates resolves a security bypass vulnerability that could lead to information disclosure (CVE-2015-3114). This updates resolves type confusion vulnerabilities that could lead to code execution (CVE-2015-3119, CVE-2015-3120, CVE-2015-3121, CVE-2015-3122, CVE-2015-4433). This updates resolves use-after-free vulnerabilities that could lead to code execution (CVE-2015-3118, CVE-2015-3124, CVE-2015-5117, CVE-2015-3127, CVE-2015-3128, CVE-2015-3129, CVE-2015-3131, CVE-2015-3132, CVE-2015-3136, CVE-2015-3137, CVE-2015-4428, CVE-2015-4430, CVE-2015-5119). This updates resolves vulnerabilities that could be exploited to bypass the same-origin-policy and lead to information disclosure (CVE-2014-0578, CVE-2015-3115, CVE-2015-3116, CVE-2015-3125, CVE-2015-5116)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0273.html");
script_cve_id("CVE-2014-0578","CVE-2015-3114","CVE-2015-3115","CVE-2015-3116","CVE-2015-3117","CVE-2015-3118","CVE-2015-3119","CVE-2015-3120","CVE-2015-3121","CVE-2015-3122","CVE-2015-3123","CVE-2015-3124","CVE-2015-3125","CVE-2015-3126","CVE-2015-3127","CVE-2015-3128","CVE-2015-3129","CVE-2015-3130","CVE-2015-3131","CVE-2015-3132","CVE-2015-3133","CVE-2015-3134","CVE-2015-3135","CVE-2015-3136","CVE-2015-3137","CVE-2015-4428","CVE-2015-4429","CVE-2015-4430","CVE-2015-4431","CVE-2015-4432","CVE-2015-4433","CVE-2015-5116","CVE-2015-5117","CVE-2015-5118","CVE-2015-5119");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0273");
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
if ((res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.481~1.mga5.nonfree", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
