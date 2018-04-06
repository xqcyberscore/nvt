# OpenVAS Vulnerability Test
# $Id: deb_2662.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2662-1 using nvtgen 1.0
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

tag_affected  = "xen on Debian Linux";
tag_insight   = "Xen is a hypervisor providing services that allow multiple computer operating
systems to execute on the same computer hardware concurrently.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.9.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.";
tag_summary   = "Multiple vulnerabilities have been discovered in the Xen hypervisor. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2013-1917 
The SYSENTER instruction can be used by PV guests to accelerate
system call processing. This instruction, however, leaves the EFLAGS
register mostly unmodified. This can be used by malicious or buggy
user space to cause the entire host to crash.

CVE-2013-1919 
Various IRQ related access control operations may not have the
intended effect, potentially permitting a stub domain to grant its
client domain access to an IRQ it doesn't have access to itself.
This can be used by malicious or buggy stub domains kernels to mount
a denial of service attack possibly affecting the whole system.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892662");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1917", "CVE-2013-1919");
    script_name("Debian Security Advisory DSA 2662-1 (xen - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-04-18 00:00:00 +0200 (Thu, 18 Apr 2013)");
    script_tag(name: "cvss_base", value:"4.7");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2662.html");


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
if ((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-5.9", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
