# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0412.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131101");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-26 09:35:59 +0200 (Mon, 26 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0412");
script_tag(name: "insight", value: "Updated java-1.8.0-openjdk packages fix security vulnerabilities: Multiple flaws were discovered in the CORBA, Libraries, RMI, Serialization, and 2D components in OpenJDK. An untrusted Java application or applet could use these flaws to completely bypass Java sandbox restrictions (CVE-2015-4835, CVE-2015-4881, CVE-2015-4843, CVE-2015-4883, CVE-2015-4860, CVE-2015-4805, CVE-2015-4844). Multiple denial of service flaws were found in the JAXP component in OpenJDK. A specially crafted XML file could cause a Java application using JAXP to consume an excessive amount of CPU and memory when parsed (CVE-2015-4803, CVE-2015-4893, CVE-2015-4911). A flaw was found in the way the Libraries component in OpenJDK handled certificate revocation lists (CRL). In certain cases, CRL checking code could fail to report a revoked certificate, causing the application to accept it as trusted (CVE-2015-4868). It was discovered that the Security component in OpenJDK failed to properly check if a certificate satisfied all defined constraints. In certain cases, this could cause a Java application to accept an X.509 certificate which does not meet requirements of the defined policy (CVE-2015-4872). Multiple flaws were found in the Libraries, 2D, CORBA, JAXP, JGSS, and RMI components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions (CVE-2015-4806, CVE-2015-4840, CVE-2015-4882, CVE-2015-4842, CVE-2015-4734, CVE-2015-4903)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0412.html");
script_cve_id("CVE-2015-4803","CVE-2015-4805","CVE-2015-4806","CVE-2015-4734","CVE-2015-4835","CVE-2015-4840","CVE-2015-4842","CVE-2015-4843","CVE-2015-4844","CVE-2015-4860","CVE-2015-4868","CVE-2015-4872","CVE-2015-4881","CVE-2015-4882","CVE-2015-4883","CVE-2015-4893","CVE-2015-4903","CVE-2015-4911");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0412");
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
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
