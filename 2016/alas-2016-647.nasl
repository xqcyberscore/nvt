# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-647.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
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
script_oid("1.3.6.1.4.1.25623.1.0.120637");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-02-11 07:16:45 +0200 (Thu, 11 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-647");
script_tag(name: "insight", value: "An out-of-bounds write flaw was found in the JPEG image format decoder in the AWT component in OpenJDK. A specially crafted JPEG image could cause a Java application to crash or, possibly execute arbitrary code. An untrusted Java application or applet could use this flaw to bypass Java sandbox restrictions. (CVE-2016-0483 )A flaw was found in the way TLS 1.2 could use the MD5 hash function for signing ServerKeyExchange and Client Authentication packets during a TLS handshake. A man-in-the-middle attacker able to force a TLS connection to use the MD5 hash function could use this flaw to conduct collision attacks to impersonate a TLS server or an authenticated TLS client. (CVE-2015-7575 )Integer signedness issues were discovered in IndicRearrangementProcessor and IndicRearrangementProcessor2 in the ICU Layout Engine. A specially crafted font file could cause an application using ICU to parse untrusted fonts to crash and, possibly, execute arbitrary code. (CVE-2016-0494 )It was discovered that the password-based encryption (PBE) implementation in the Libraries component in OpenJDK used an incorrect key length. This could, in certain cases, lead to generation of keys that were weaker than expected. (CVE-2016-0475 )A flaw was found in the deserialization of the URL class in the Networking component of OpenJDK.  Deserialization of the specially crafted data could result in creation of the URL object with an inconsistent state.  An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions. (CVE-2016-0402 )It was discovered that the JAXP component in OpenJDK did not properly enforce the totalEntitySizeLimit limit. An attacker able to make a Java application process a specially crafted XML file could use this flaw to make the application consume an excessive amount of memory. (CVE-2016-0466 )It was discovered that the RMIConnector and RMIConnectionImpl classes in the JMX component of OpenJDK could log sensitive information such as user passwords in its debug log, possibly leading the exposure of the information. (CVE-2016-0448 )"); 
script_tag(name : "solution", value : "Run yum update java-1.8.0-openjdk to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-647.html");
script_cve_id("CVE-2016-0483","CVE-2015-7575","CVE-2016-0494","CVE-2016-0475","CVE-2016-0402","CVE-2016-0466","CVE-2016-0448");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
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
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
