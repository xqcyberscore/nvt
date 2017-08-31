# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0447.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131132");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-11-17 11:00:00 +0200 (Tue, 17 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0447");
script_tag(name: "insight", value: "Updated iceape packages fix security issues: Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-4513) Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 42.0 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-4514) Mozilla Firefox before 42.0, when NTLM v1 is enabled for HTTP authentication, allows remote attackers to obtain sensitive hostname information by constructing a crafted web site that sends an NTLM request and reads the Workstation field of an NTLM type 3 message. (CVE-2015-4515) The Reader View implementation in Mozilla Firefox before 42.0 has an improper whitelist, which makes it easier for remote attackers to bypass the Content Security Policy (CSP) protection mechanism and conduct cross-site scripting (XSS) attacks via vectors involving SVG animations and the about:reader URL. (CVE-2015-4518) The Add-on SDK in Mozilla Firefox before 42.0 misinterprets a script: false panel setting, which makes it easier for remote attackers to conduct cross-site scripting (XSS) attacks via inline JavaScript code that is executed within a third-party extension. (CVE-2015-7187) Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 allow remote attackers to bypass the Same Origin Policy for an IP address origin, and conduct cross-site scripting (XSS) attacks, by appending whitespace characters to an IP address string. (CVE-2015-7188) Race condition in the JPEGEncoder function in Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 allows remote attackers to execute arbitrary code or cause a denial of service (heap-based buffer overflow) via vectors involving a CANVAS element and crafted JavaScript code. (CVE-2015-7189) Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 improperly follow the CORS cross-origin request algorithm for the POST method in situations involving an unspecified Content-Type header manipulation, which allows remote attackers to bypass the Same Origin Policy by leveraging the lack of a preflight-request step. (CVE-2015-7193) Buffer underflow in libjar in Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted ZIP archive. (CVE-2015-7194) The URL parsing implementation in Mozilla Firefox before 42.0 improperly recognizes escaped characters in hostnames within Location headers, which allows remote attackers to obtain sensitive information via vectors involving a redirect. (CVE-2015-7195) Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4, when a Java plugin is enabled, allow remote attackers to cause a denial of service (incorrect garbage collection and application crash) or possibly execute arbitrary code via a crafted Java applet that deallocates an in-use JavaScript wrapper. (CVE-2015-7196) Buffer overflow in the rx::TextureStorage11 class in ANGLE, as used in Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4, allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via crafted texture data. (CVE-2015-7198) The (1) AddWeightedPathSegLists and (2) SVGPathSegListSMILType::Interpolate functions in Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 lack status checking, which allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a crafted SVG document. (CVE-2015-7199) The CryptoKey interface implementation in Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 lacks status checking, which allows attackers to have an unspecified impact via vectors related to a cryptographic key. (CVE-2015-7200) Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 improperly control the ability of a web worker to create a WebSocket object, which allows remote attackers to bypass intended mixed-content restrictions via crafted JavaScript code. (CVE-2015-7197)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0447.html");
script_cve_id("CVE-2015-4513","CVE-2015-4514","CVE-2015-4515","CVE-2015-4518","CVE-2015-7187","CVE-2015-7188","CVE-2015-7189","CVE-2015-7193","CVE-2015-7194","CVE-2015-7195","CVE-2015-7196","CVE-2015-7197","CVE-2015-7198","CVE-2015-7199","CVE-2015-7200");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0447");
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
if ((res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.39~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
