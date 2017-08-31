# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0477.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131152");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-12-17 10:49:11 +0200 (Thu, 17 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0477");
script_tag(name: "insight", value: "Updated firefox packages fix security vulnerabilities: Multiple memory safety issues in Firefox were discovered. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit these to cause a denial of service via application crash, or execute arbitrary code with the privileges of the user invoking Firefox (CVE-2015-7201). Ronald Crane discovered a buffer overflow through code inspection. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a denial of service via application crash, or execute arbitrary code with the privileges of the user invoking Firefox (CVE-2015-7205). Looben Yang discovered a use-after-free in WebRTC when closing channels in some circumstances. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a denial of service via application crash, or execute arbitrary code with the privileges of the user invoking Firefox (CVE-2015-7210). Abhishek Arya discovered an integer overflow when allocating large textures. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a denial of service via application crash, or execute arbitrary code with the privileges of the user invoking Firefox (CVE-2015-7212). Ronald Crane discovered an integer overflow when processing MP4 format video in some circumstances. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a denial of service via application crash, or execute arbitrary code with the privileges of the user invoking Firefox (CVE-2015-7213). Tsubasa Iinuma discovered a way to bypass same-origin restrictions using data: and view-source: URLs. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to obtain sensitive information and read local files (CVE-2015-7214). Gerald Squelart discovered an integer underflow in the libstagefright library when parsing MP4 format video in some circumstances. If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a denial of service via application crash, or execute arbitrary code with the privileges of the user invoking Firefox (CVE-2015-7222)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0477.html");
script_cve_id("CVE-2015-7201","CVE-2015-7205","CVE-2015-7210","CVE-2015-7212","CVE-2015-7213","CVE-2015-7214","CVE-2015-7222");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0477");
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
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.11~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.21.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.5.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~38.5.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
