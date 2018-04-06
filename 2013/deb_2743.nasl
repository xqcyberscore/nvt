# OpenVAS Vulnerability Test
# $Id: deb_2743.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2743-1 using nvtgen 1.0
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

tag_affected  = "kfreebsd-9 on Debian Linux";
tag_insight   = "The FreeBSD kernel is the core of the FreeBSD operating system.";
tag_solution  = "For the stable distribution (wheezy), these problems has been fixed in
version 9.0-10+deb70.3.

We recommend that you upgrade your kfreebsd-9 packages.";
tag_summary   = "Several vulnerabilities have been discovered in the FreeBSD kernel
that may lead to a privilege escalation or information leak. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2013-3077 
Clement Lecigne from the Google Security Team reported an integer
overflow in computing the size of a temporary buffer in the IP
multicast code, which can result in a buffer which is too small
for the requested operation. An unprivileged process can read or
write pages of memory which belong to the kernel. These may lead
to exposure of sensitive information or allow privilege
escalation.

CVE-2013-4851 
Rick Macklem, Christopher Key and Tim Zingelman reported that the
FreeBSD kernel incorrectly uses client supplied credentials
instead of the one configured in exports(5) when filling out the
anonymous credential for a NFS export, when -network or -host
restrictions are used at the same time. The remote client may
supply privileged credentials (e.g. the root user) when accessing
a file under the NFS share, which will bypass the normal access
checks.

CVE-2013-5209 
Julian Seward and Michael Tuexen reported a kernel memory
disclosure when initializing the SCTP state cookie being sent in
INIT-ACK chunks, a buffer allocated from the kernel stack is not
completely initialized. Fragments of kernel memory may be
included in SCTP packets and transmitted over the network. For
each SCTP session, there are two separate instances in which a
4-byte fragment may be transmitted.

This memory might contain sensitive information, such as portions
of the file cache or terminal buffers. This information might be
directly useful, or it might be leveraged to obtain elevated
privileges in some way. For example, a terminal buffer might
include an user-entered password.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892743");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-5209", "CVE-2013-3077", "CVE-2013-4851");
    script_name("Debian Security Advisory DSA 2743-1 (kfreebsd-9 - privilege escalation/information leak)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-08-27 00:00:00 +0200 (Tue, 27 Aug 2013)");
    script_tag(name: "cvss_base", value:"7.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2743.html");


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
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9-486", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9-686", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9-686-smp", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9-amd64", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9-malta", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9-xen", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-486", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-686", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-686-smp", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-amd64", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-malta", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-xen", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9-486", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9-686", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9-686-smp", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9-amd64", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9-malta", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9-xen", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-486", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-686", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-686-smp", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-amd64", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-malta", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-xen", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfreebsd-source-9.0", ver:"9.0-10+deb70.3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
