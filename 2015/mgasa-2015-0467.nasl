# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0467.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131149");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-12-10 11:05:52 +0200 (Thu, 10 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0467");
script_tag(name: "insight", value: "Chromium-browser 47.0.2526.73 fixes several security issues: Use-after-free bugs in AppCache (CVE-2015-6765, CVE-2015-6766, CVE-2015-6767). Cross-origin bypass problems in DOM (CVE-2015-6768, CVE-2015-6770, CVE-2015-6772). A cross-origin bypass problem in core (CVE-2015-6769). Out of bounds access bugs in v8 (CVE-2015-6771, CVE-2015-6764). An out of bounds access in Skia (CVE-2015-6773). A use-after-free bug in the Extensions component (CVE-2015-6774). Type confusion in PDFium (CVE-2015-6775). Out of bounds accesses in PDFium (CVE-2015-6776, CVE-2015-6778). A use-after-free bug in DOM (CVE-2015-6777). A scheme bypass in PDFium (CVE-2015-6779). A use-after-free bug in Infobars (CVE-2015-6780). An integer overflow in Sfntly (CVE-2015-6781). Content spoofing in Omnibox (CVE-2015-6782). An escaping issue in saved pages (CVE-2015-6784). A wildcard matching issue in CSP (CVE-2015-6785). A scheme bypass in CSP (CVE-2015-6786). Various fixes from internal audits, fuzzing and other initiatives (CVE-2015-6787). Multiple vulnerabilities in V8 fixed in the 4.7 branch, up to version 4.7.80.23."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0467.html");
script_cve_id("CVE-2015-6764","CVE-2015-6765","CVE-2015-6766","CVE-2015-6767","CVE-2015-6768","CVE-2015-6769","CVE-2015-6770","CVE-2015-6771","CVE-2015-6772","CVE-2015-6773","CVE-2015-6774","CVE-2015-6775","CVE-2015-6776","CVE-2015-6777","CVE-2015-6778","CVE-2015-6779","CVE-2015-6780","CVE-2015-6782","CVE-2015-6784","CVE-2015-6785","CVE-2015-6786","CVE-2015-6787");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0467");
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
if ((res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~47.0.2526.73~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
