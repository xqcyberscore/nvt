# OpenVAS Vulnerability Test
# $Id: deb_2737.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2737-1 using nvtgen 1.0
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

tag_affected  = "swift on Debian Linux";
tag_insight   = "OpenStack Object Storage (code-named Swift) is open source software for
creating redundant, scalable object storage using clusters of standardized
servers to store petabytes of accessible data. It is not a file system or
real-time data storage system, but rather a long-term storage system for a
more permanent type of static data that can be retrieved, leveraged, and then
updated if necessary. Primary examples of data that best fit this type of
storage model are virtual machine images, photo storage, email storage and
backup archiving. Having no central 'brain' or master point of control
provides greater scalability, redundancy and permanence.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 1.4.8-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.0-6.

We recommend that you upgrade your swift packages.";
tag_summary   = "Several vulnerabilities have been discovered in Swift, the Openstack
object storage. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2013-2161 
Alex Gaynor from Rackspace reported a vulnerability in XML
handling within Swift account servers. Account strings were
unescaped in xml listings, and an attacker could potentially
generate unparsable or arbitrary XML responses which may be
used to leverage other vulnerabilities in the calling software.

CVE-2013-4155 
Peter Portante from Red Hat reported a vulnerability in Swift.
By issuing requests with an old X-Timestamp value, an
authenticated attacker can fill an object server with superfluous
object tombstones, which may significantly slow down subsequent
requests to that object server, facilitating a Denial of Service
attack against Swift clusters.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892737");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-2161", "CVE-2013-4155");
    script_name("Debian Security Advisory DSA 2737-1 (swift - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-08-12 00:00:00 +0200 (Mon, 12 Aug 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2737.html");


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
if ((res = isdpkgvuln(pkg:"python-swift", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swift", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swift-account", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swift-container", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swift-doc", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swift-object", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swift-proxy", ver:"1.4.8-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
