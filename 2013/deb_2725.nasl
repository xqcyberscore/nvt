# OpenVAS Vulnerability Test
# $Id: deb_2725.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2725-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");

tag_affected  = "tomcat6 on Debian Linux";
tag_insight   = "Apache Tomcat implements the Java Servlet and the JavaServer Pages (JSP)
specifications from Sun Microsystems, and provides a 'pure Java' HTTP web
server environment for Java code to run.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 6.0.35-1+squeeze3. This update also provides fixes for
CVE-2012-2733,
CVE-2012-3546,
CVE-2012-4431,
CVE-2012-4534,
CVE-2012-5885,
CVE-2012-5886 and
CVE-2012-5887 
,
which were all fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in
version 6.0.35-6+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your tomcat6 packages.";
tag_summary   = "Two security issues have been found in the Tomcat servlet and JSP engine:

CVE-2012-3544 
The input filter for chunked transfer encodings could trigger high
resource consumption through malformed CRLF sequences, resulting in
denial of service.

CVE-2013-2067 
The FormAuthenticator module was vulnerable to session fixation.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892725");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-4534", "CVE-2012-3544", "CVE-2013-2067", "CVE-2012-5885", "CVE-2012-5887", "CVE-2012-4431", "CVE-2012-2733", "CVE-2012-5886", "CVE-2012-3546");
    script_name("Debian Security Advisory DSA 2725-1 (tomcat6 - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-07-18 00:00:00 +0200 (Thu, 18 Jul 2013)");
    script_tag(name: "cvss_base", value:"6.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2725.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.35-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libservlet2.4-java", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-extras", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.35-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
