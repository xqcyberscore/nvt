# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-527.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120057");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:16:25 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2015-527");
script_tag(name: "insight", value: "It was discovered that JBoss Web / Apache Tomcat did not limit the length of chunk sizes when using chunked transfer encoding. A remote attacker could use this flaw to perform a denial of service attack against JBoss Web / Apache Tomcat by streaming an unlimited quantity of data, leading to excessive consumption of server resources. (CVE-2014-0075 )It was found that the org.apache.catalina.servlets.DefaultServlet implementation in JBoss Web / Apache Tomcat allowed the definition of XML External Entities (XXEs) in provided XSLTs. A malicious application could use this to circumvent intended security restrictions to disclose sensitive information. (CVE-2014-0096 )It was found that JBoss Web / Apache Tomcat did not check for overflowing values when parsing request content length headers. A remote attacker could use this flaw to perform an HTTP request smuggling attack on a JBoss Web / Apache Tomcat server located behind a reverse proxy that processed the content length header correctly. (CVE-2014-0099 )It was discovered that the ChunkedInputFilter in Tomcat did not fail subsequent attempts to read input after malformed chunked encoding was detected. A remote attacker could possibly use this flaw to make Tomcat process part of the request body as new request, or cause a denial of service. (CVE-2014-0227 )"); 
script_tag(name : "solution", value : "Run yum update tomcat8 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-527.html");
script_cve_id("CVE-2014-0075","CVE-2014-0096","CVE-2014-0099","CVE-2014-0227");
script_tag(name:"cvss_base", value:"6.4");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"tomcat8-admin-webapps", rpm:"tomcat8-admin-webapps~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-servlet", rpm:"tomcat8-servlet~3.1~api~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-docs-webapp", rpm:"tomcat8-docs-webapp~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-jsp", rpm:"tomcat8-jsp~2.3~api~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-webapps", rpm:"tomcat8-webapps~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-log4j", rpm:"tomcat8-log4j~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-javadoc", rpm:"tomcat8-javadoc~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-lib", rpm:"tomcat8-lib~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-el", rpm:"tomcat8-el~3.0~api~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8", rpm:"tomcat8~8.0.20~1.53.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
