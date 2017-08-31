# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-679.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.120669");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-03-31 08:02:12 +0300 (Thu, 31 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-679");
script_tag(name: "insight", value: "ResourceLinkFactory.setGlobalContext() is a public method and was discovered to be accessible by web applications running under a security manager without any checks. This allowed a malicious web application to inject a malicious global context that could in turn be used to disrupt other web applications and/or read and write data owned by other web applications. (CVE-2016-0763 )A session fixation vulnerability was discovered that might allow remote attackers to hijack web sessions by leveraging use of a requestedSessionSSL field for an unintended request when different session settings are used for deployments of multiple versions of the same web application. (CVE-2015-5346 )The Manager and Host Manager applications were discovered to establish sessions and send CSRF tokens for arbitrary new requests, which allows remote attackers to bypass a CSRF protection mechanism by using a token. (CVE-2015-5351 )The session-persistence implementation was discovered to mishandle session attributes, which allows remote authenticated users to bypass intended SecurityManager restrictions and execute arbitrary code in a privileged context via a web application that places a crafted object in a session. (CVE-2016-0714 )It was discovered that org.apache.catalina.manager.StatusManagerServlet was not placed on the org/apache/catalina/core/RestrictedServlets.properties list, which allows remote authenticated users to bypass intended SecurityManager restrictions and read arbitrary HTTP requests, and consequently discover session ID values, via a crafted web application. (CVE-2016-0706 )"); 
script_tag(name : "solution", value : "Run yum update tomcat8 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-679.html");
script_cve_id("CVE-2016-0763","CVE-2015-5346","CVE-2015-5351","CVE-2016-0714","CVE-2016-0706");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"tomcat8", rpm:"tomcat8~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-javadoc", rpm:"tomcat8-javadoc~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-docs-webapp", rpm:"tomcat8-docs-webapp~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-servlet", rpm:"tomcat8-servlet~3.1~api~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-admin-webapps", rpm:"tomcat8-admin-webapps~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-lib", rpm:"tomcat8-lib~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-jsp", rpm:"tomcat8-jsp~2.3~api~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-webapps", rpm:"tomcat8-webapps~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-log4j", rpm:"tomcat8-log4j~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat8-el", rpm:"tomcat8-el~3.0~api~8.0.32~1.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
