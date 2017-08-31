# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-88.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120133");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:18:16 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2012-88");
script_tag(name: "insight", value: "Multiple flaws were discovered in the CORBA (Common Object Request Broker Architecture) implementation in Java. A malicious Java application or applet could use these flaws to bypass Java sandbox restrictions or modify immutable object data. (CVE-2012-1711 , CVE-2012-1719 )It was discovered that the SynthLookAndFeel class from Swing did not properly prevent access to certain UI elements from outside the current application context. A malicious Java application or applet could use this flaw to crash the Java Virtual Machine, or bypass Java sandbox restrictions. (CVE-2012-1716 )Multiple flaws were discovered in the font manager's layout lookup implementation. A specially-crafted font file could cause the Java Virtual Machine to crash or, possibly, execute arbitrary code with the privileges of the user running the virtual machine. (CVE-2012-1713 )Multiple flaws were found in the way the Java HotSpot Virtual Machine verified the bytecode of the class file to be executed. A specially-crafted Java application or applet could use these flaws to crash the Java Virtual Machine, or bypass Java sandbox restrictions. (CVE-2012-1723 , CVE-2012-1725 )It was discovered that the Java XML parser did not properly handle certain XML documents. An attacker able to make a Java application parse a specially-crafted XML file could use this flaw to make the XML parser enter an infinite loop. (CVE-2012-1724 )It was discovered that the Java security classes did not properly handle Certificate Revocation Lists (CRL). CRL containing entries with duplicate certificate serial numbers could have been ignored. (CVE-2012-1718 )It was discovered that various classes of the Java Runtime library could create temporary files with insecure permissions. A local attacker could use this flaw to gain access to the content of such temporary files. (CVE-2012-1717 )"); 
script_tag(name : "solution", value : "Run yum update java-1.6.0-openjdk to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-88.html");
script_cve_id("CVE-2012-1724","CVE-2012-1718","CVE-2012-1723","CVE-2012-1717","CVE-2012-1716","CVE-2012-1711","CVE-2012-1713","CVE-2012-1719","CVE-2012-1725");
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
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~52.1.11.3.45.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~52.1.11.3.45.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~52.1.11.3.45.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~52.1.11.3.45.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~52.1.11.3.45.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~52.1.11.3.45.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
