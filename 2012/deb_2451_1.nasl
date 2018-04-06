# OpenVAS Vulnerability Test
# $Id: deb_2451_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2451-1 (puppet)
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
tag_insight = "Several vulnerabilities have been discovered in puppet, a centralized
configuration management system.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2012-1906

Puppet is using predictable temporary file names when downloading
Mac OS X package files.  This allows a local attacker to either
overwrite arbitrary files on the system or to install an arbitrary
package.

CVE-2012-1986

When handling requests for a file from a remote filebucket, puppet
can be tricked into overwriting its defined location for filebucket
storage.  This allows an authorized attacker with access to the puppet
master to read arbitrary files.

CVE-2012-1987

Puppet is incorrectly handling filebucket store requests.  This allows
an attacker to perform denial of service attacks against puppet by
resource exhaustion.

CVE-2012-1988

Puppet is incorrectly handling filebucket requests.  This allows an
attacker with access to the certificate on the agent and an unprivileged
account on puppet master to execute arbitrary code via crafted file
path names and making a filebucket request.


For the stable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze5.

For the testing distribution (wheezy), this problem has been fixed in
version 2.7.13-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.7.13-1.

We recommend that you upgrade your puppet packages.";
tag_summary = "The remote host is missing an update to puppet
announced via advisory DSA 2451-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202451-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71255");
 script_cve_id("CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:56:51 -0400 (Mon, 30 Apr 2012)");
 script_name("Debian Security Advisory DSA 2451-1 (puppet)");



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
if((res = isdpkgvuln(pkg:"puppet", ver:"2.6.2-5+squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.2-5+squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet-el", ver:"2.6.2-5+squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.6.2-5+squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.6.2-5+squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.6.2-5+squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet-el", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster-common", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster-passenger", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.7.13-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
