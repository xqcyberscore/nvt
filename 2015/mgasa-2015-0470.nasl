# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0470.nasl 4513 2016-11-15 09:37:48Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131150");
script_version("$Revision: 4513 $");
script_tag(name:"creation_date", value:"2015-12-11 07:23:47 +0200 (Fri, 11 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 10:37:48 +0100 (Tue, 15 Nov 2016) $");
script_name("Mageia Linux Local Check: mgasa-2015-0470");
script_tag(name: "insight", value: "Updated chromium-browser-stable packages fix security vulnerabilities: Type confusion in extensions (CVE-2015-6788). Use-after-free in Blink (CVE-2015-6789). Escaping issue in saved pages (CVE-2015-6790). Various fixes from internal audits, fuzzing and other initiatives (CVE-2015-6791)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0470.html");
script_cve_id("CVE-2015-6788","CVE-2015-6789","CVE-2015-6790","CVE-2015-6791");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0470");
script_summary("Mageia Linux Local Security Checks mgasa-2015-0470");
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
if ((res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~47.0.2526.80~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
