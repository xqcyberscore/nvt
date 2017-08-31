# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-570.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120041");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:15:57 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2015-570");
script_tag(name: "insight", value: "Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and RMI components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2015-4760 , CVE-2015-2628 , CVE-2015-4731 , CVE-2015-2590 , CVE-2015-4732 , CVE-2015-4733 )A flaw was found in the way the Libraries component of OpenJDK verified Online Certificate Status Protocol (OCSP) responses. An OCSP response with no nextUpdate date specified was incorrectly handled as having unlimited validity, possibly causing a revoked X.509 certificate to be interpreted as valid. (CVE-2015-4748 )It was discovered that the JCE component in OpenJDK failed to use constant time comparisons in multiple cases. An attacker could possibly use these flaws to disclose sensitive information by measuring the time used to perform operations using these non-constant time comparisons. (CVE-2015-2601 )A flaw was found in the RC4 encryption algorithm. When using certain keys for RC4 encryption, an attacker could obtain portions of the plain text from the cipher text without the knowledge of the encryption key. (CVE-2015-2808 )Please note that with this update, OpenJDK now disables RC4 TLS/SSL cipher suites by default to address the CVE-2015-2808  issue.A flaw was found in the way the TLS protocol composed the Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could use this flaw to force the use of weak 512 bit export-grade keys during the key exchange, allowing them do decrypt all traffic. (CVE-2015-4000 )Please note that this update forces the TLS/SSL client implementation in OpenJDK to reject DH key sizes below 768 bits, which prevents sessions to be downgraded to export-grade keys.It was discovered that the JNDI component in OpenJDK did not handle DNS resolutions correctly. An attacker able to trigger such DNS errors could cause a Java application using JNDI to consume memory and CPU time, and possibly block further DNS resolution. (CVE-2015-4749 )Multiple information leak flaws were found in the JMX and 2D components in OpenJDK. An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions. (CVE-2015-2621 , CVE-2015-2632 )A flaw was found in the way the JSSE component in OpenJDK performed X.509 certificate identity verification when establishing a TLS/SSL connection to a host identified by an IP address. In certain cases, the certificate was accepted as valid if it was issued for a host name to which the IP address resolves rather than for the IP address. (CVE-2015-2625 )"); 
script_tag(name : "solution", value : "Run yum update java-1.7.0-openjdk to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-570.html");
script_cve_id("CVE-2015-4748","CVE-2015-2628","CVE-2015-2625","CVE-2015-2632","CVE-2015-2601","CVE-2015-4732","CVE-2015-2621","CVE-2015-2590","CVE-2015-4731","CVE-2015-4760","CVE-2015-4000","CVE-2015-2808","CVE-2015-4733","CVE-2015-4749");
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
if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-debuginfo", rpm:"java-1.7.0-openjdk-debuginfo~1.7.0.85~2.6.1.3.61.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.85~2.6.1.3.61.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.85~2.6.1.3.61.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.85~2.6.1.3.61.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.85~2.6.1.3.61.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.85~2.6.1.3.61.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
