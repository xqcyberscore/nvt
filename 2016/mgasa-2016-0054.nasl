# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0054.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131224");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-02-11 07:22:22 +0200 (Thu, 11 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0054");
script_tag(name: "insight", value: "Note: this package was called polarssl, but is now called mbed tls. The PolarSSL software is now called mbed TLS. Heap-based buffer overflow in mbed TLS (formerly PolarSSL) 1.3.x before 1.3.14 allows remote SSL servers to cause a denial of service (client crash) and possibly execute arbitrary code via a long hostname to the server name indication (SNI) extension, which is not properly handled when creating a ClientHello message (CVE-2015-5291). Heap-based buffer overflow in mbed TLS (formerly PolarSSL) 1.3.x before 1.3.14 allows remote SSL servers to cause a denial of service (client crash) and possibly execute arbitrary code via a long session ticket name to the session ticket extension, which is not properly handled when creating a ClientHello message to resume a session (CVE-2015-8036). The mbedtls package has been updated to version 1.3.16, which contains several other bug fixes, security fixes, and security enhancements. The hiawatha package, which uses the polarssl/mbedtls library, has been updated to version 9.13 for improved compatibility. The belle-sip library package has been updated to version 1.4.2 for improved compatibility and the linphone package has been rebuilt against mbedtls. The pdns package has also been rebuilt against mbedtls."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0054.html");
script_cve_id("CVE-2015-5291","CVE-2015-8036");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0054");
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
if ((res = isrpmvuln(pkg:"mbedtls", rpm:"mbedtls~1.3.16~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"hiawatha", rpm:"hiawatha~9.13~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"belle-sip", rpm:"belle-sip~1.4.2~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"linphone", rpm:"linphone~3.8.1~1.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"pdns", rpm:"pdns~3.3.3~1.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
