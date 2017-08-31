# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-283.nasl 6637 2017-07-10 09:58:13Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120002");
script_version("$Revision: 6637 $");
script_tag(name:"creation_date", value:"2015-09-08 13:14:37 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2014-283");
script_tag(name: "insight", value: "An input validation flaw was discovered in the font layout engine in the 2D component. A specially crafted font file could trigger a Java Virtual Machine memory corruption when processed. An untrusted Java application or applet could possibly use this flaw to bypass Java sandbox restrictions. (CVE-2013-5907 )Multiple improper permission check issues were discovered in the CORBA and JNDI components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2014-0428 , CVE-2014-0422 )Multiple improper permission check issues were discovered in the Serviceability, Security, CORBA, JAAS, JAXP, and Networking components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2014-0373 , CVE-2013-5878 , CVE-2013-5910 , CVE-2013-5896 , CVE-2013-5884 , CVE-2014-0416 , CVE-2014-0376 , CVE-2014-0368 )It was discovered that the Beans component did not restrict processing of XML external entities. This flaw could cause a Java application using Beans to leak sensitive information, or affect application availability. (CVE-2014-0423 )It was discovered that the JSSE component could leak timing information during the TLS/SSL handshake. This could possibly lead to a disclosure of information about the used encryption keys. (CVE-2014-0411 )"); 
script_tag(name : "solution", value : "Run yum update java-1.6.0-openjdk to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-283.html");
script_cve_id("CVE-2014-0368","CVE-2014-0411","CVE-2013-5878","CVE-2013-5910","CVE-2014-0416","CVE-2014-0373","CVE-2013-5907","CVE-2013-5884","CVE-2013-5896","CVE-2014-0428","CVE-2014-0422","CVE-2014-0376","CVE-2014-0423");
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
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~66.1.13.1.62.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~66.1.13.1.62.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~66.1.13.1.62.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~66.1.13.1.62.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~66.1.13.1.62.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~66.1.13.1.62.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
