# OpenVAS Vulnerability Test
# $Id: deb_2790.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2790-1 using nvtgen 1.0
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

tag_affected  = "nss on Debian Linux";
tag_insight   = "nss is a set of libraries designed to support cross-platform development
of security-enabled client and server applications.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 2:3.14.4-1.

The packages in the stable distribution were updated to the latest patch
release 3.14.4 of the library to also include a regression bugfix for a
flaw that affects the libpkix certificate verification cache. More
information can be found via:

https://developer.mozilla.org/en-US/docs/NSS/NSS_3.14.4_release_notes 
For the testing distribution (jessie), this problem has been fixed in
version 2:3.15.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 2:3.15.2-1.

We recommend that you upgrade your nss packages.";
tag_summary   = "A flaw was found in the way the Mozilla Network Security Service library
(nss) read uninitialized data when there was a decryption failure. A
remote attacker could use this flaw to cause a denial of service
(application crash) for applications linked with the nss library.

The oldstable distribution (squeeze) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892790");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1739");
    script_name("Debian Security Advisory DSA 2790-1 (nss - uninitialized memory read)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-11-02 00:00:00 +0100 (Sat, 02 Nov 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2790.html");


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
if ((res = isdpkgvuln(pkg:"libnss3", ver:"2:3.14.4-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-1d", ver:"2:3.14.4-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-dbg", ver:"2:3.14.4-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-dev", ver:"2:3.14.4-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-tools", ver:"2:3.14.4-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
