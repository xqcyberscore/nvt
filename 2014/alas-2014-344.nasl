# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-344.nasl 6735 2017-07-17 09:56:49Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120469");
script_version("$Revision: 6735 $");
script_tag(name:"creation_date", value:"2015-09-08 13:27:08 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-344");
script_tag(name: "insight", value: "It was found that when Tomcat processed a series of HTTP requests in which at least one request contained either multiple content-length headers, or one content-length header with a chunked transfer-encoding header, Tomcat would incorrectly handle the request. A remote attacker could use this flaw to poison a web cache, perform cross-site scripting (XSS) attacks, or obtain sensitive information from other requests. (CVE-2013-4286 )It was discovered that the fix for CVE-2012-3544  did not properly resolve a denial of service flaw in the way Tomcat processed chunk extensions and trailing headers in chunked requests. A remote attacker could use this flaw to send an excessively long request that, when processed by Tomcat, could consume network bandwidth, CPU, and memory on the Tomcat server. Note that chunked transfer encoding is enabled by default. (CVE-2013-4322 )A denial of service flaw was found in the way Apache Commons FileUpload handled small-sized buffers used by MultipartStream. A remote attacker could use this flaw to create a malformed Content-Type header for a multipart request, causing JBoss Web to enter an infinite loop when processing such an incoming request. (CVE-2014-0050 )"); 
script_tag(name : "solution", value : "Run yum update tomcat6 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-344.html");
script_cve_id("CVE-2012-3544", "CVE-2014-0050", "CVE-2013-4286", "CVE-2013-4322");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"tomcat6-servlet", rpm:"tomcat6-servlet~2.5~api~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-jsp", rpm:"tomcat6-jsp~2.1~api~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6-el", rpm:"tomcat6-el~2.1~api~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.39~1.4.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
