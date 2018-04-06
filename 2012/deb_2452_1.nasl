# OpenVAS Vulnerability Test
# $Id: deb_2452_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2452-1 (apache2)
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
tag_insight = "Niels Heinen noticed a security issue with the default Apache
configuration on Debian if certain scripting modules like mod_php or
mod_rivet are installed. The problem arises because the directory
/usr/share/doc, which is mapped to the URL /doc, may contain example
scripts that can be executed by requests to this URL. Although access
to the URL /doc is restricted to connections from localhost, this still
creates security issues in two specific configurations:

- - If some front-end server on the same host forwards connections to an
apache2 backend server on the localhost address, or

- - if the machine running apache2 is also used for web browsing.

Systems not meeting one of these two conditions are not known to be
vulnerable. The actual security impact depends on which packages (and
accordingly which example scripts) are installed on the system.
Possible issues include cross site scripting, code execution, or
leakage of sensitive data.

This updates removes the problematic configuration sections from the
files /etc/apache2/sites-available/default and .../default-ssl. When
upgrading, you should not blindly allow dpkg to replace those files,
though. Rather you should merge the changes, namely the removal of the
'Alias /doc /usr/share/doc' line and the related '<Directory
/usr/share/doc/>' block, into your versions of these config files.
You may also want to check if you have copied these sections to any
additional virtual host configurations.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.16-6+squeeze7.

For the testing distribution (wheezy), this problem will be fixed in
version 2.2.22-4.

For the unstable distribution (sid), this problem will be fixed in
version 2.2.22-4.

For the experimental distribution, this problem has been fixed in
version 2.4.1-3.

We recommend that you upgrade your apache2 packages and adjust your";
tag_summary = "The remote host is missing an update to apache2
announced via advisory DSA 2452-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202452-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71256");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-0216");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:57:31 -0400 (Mon, 30 Apr 2012)");
 script_name("Debian Security Advisory DSA 2452-1 (apache2)");



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
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.16-6+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.22-4", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
