# OpenVAS Vulnerability Test
# $Id: deb_2712.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2712-1 using nvtgen 1.0
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

tag_affected  = "otrs2 on Debian Linux";
tag_insight   = "OTRS is an Open source Ticket Request System (also well known as
trouble ticket system) with many features to manage customer telephone
calls and e-mails. The system is built to allow your support, sales,
pre-sales, billing, internal IT, helpdesk, etc. department to react
quickly to inbound inquiries. For a detailed documentation see package
otrs-doc-en or otrs-doc-de.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 3.1.7+dfsg1-8+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.8-1.

We recommend that you upgrade your otrs2 packages.";
tag_summary   = "It was discovered that users with a valid agent login could use
crafted URLs to bypass access control restrictions and read tickets to
which they should not have access.

The oldstable distribution (squeeze) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892712");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-4088");
    script_name("Debian Security Advisory DSA 2712-1 (otrs2 - privilege escalation)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-06-19 00:00:00 +0200 (Wed, 19 Jun 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2712.html");


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
if ((res = isdpkgvuln(pkg:"otrs", ver:"3.1.7+dfsg1-8+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"otrs2", ver:"3.1.7+dfsg1-8+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
