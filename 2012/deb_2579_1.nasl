# OpenVAS Vulnerability Test
# $Id: deb_2579_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2579-1 (apache2)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
tag_insight = "A vulnerability has been found in the Apache HTTPD Server:

CVE-2012-4557

A flaw was found when mod_proxy_ajp connects to a backend
server that takes too long to respond. Given a specific
configuration, a remote attacker could send certain requests,
putting a backend server into an error state until the retry
timeout expired. This could lead to a temporary denial of
service.

In addition, this update also adds a server side mitigation for the
following issue:

CVE-2012-4929

If using SSL/TLS data compression with HTTPS in an connection
to a web browser, man-in-the-middle attackers may obtain
plaintext HTTP headers. This issue is known as the CRIME
attack. This update of apache2 disables SSL compression by
default. A new SSLCompression directive has been backported
that may be used to re-enable SSL data compression in
environments where the CRIME attack is not an issue.
For more information, please refer to:
http://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcompression

For the stable distribution (squeeze), these problems have been fixed in
version 2.2.16-6+squeeze10.

For the testing distribution (wheezy), these problems have been fixed in
version 2.2.22-12.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.22-12.

We recommend that you upgrade your apache2 packages.";
tag_summary = "The remote host is missing an update to apache2
announced via advisory DSA 2579-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202579-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72626");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2012-4557", "CVE-2012-4929");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-12-04 11:42:48 -0500 (Tue, 04 Dec 2012)");
 script_name("Debian Security Advisory DSA 2579-1 (apache2)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");
res = "";
report = "";
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.16-6+squeeze10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.22-12", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
