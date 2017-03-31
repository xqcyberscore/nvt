# OpenVAS Vulnerability Test
# $Id: deb_3572.nasl 3604 2016-06-27 05:18:57Z antu123 $
# Auto-generated from advisory DSA 3572-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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


if(description)
{
    script_id(703572);
    script_version("$Revision: 3604 $");
    script_cve_id("CVE-2016-1236");
    script_name("Debian Security Advisory DSA 3572-1 (websvn - security update)");
    script_tag(name: "last_modification", value: "$Date: 2016-06-27 07:18:57 +0200 (Mon, 27 Jun 2016) $");
    script_tag(name: "creation_date", value: "2016-05-09 00:00:00 +0200 (Mon, 09 May 2016)");
    script_tag(name:"cvss_base", value:"4.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3572.html");

    script_summary("Debian Security Advisory DSA 3572-1 (websvn - security update)");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
    script_tag(name: "affected",  value: "websvn on Debian Linux");
    script_tag(name: "insight",   value: "WebSVN is a set of PHP scripts
that provides remote access to Subversion repositories. It supports several
repositories, can be customized, supports Apache MultiViews, and can provide
RSS feeds.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
this problem has been fixed in version 2.3.3-1.2+deb8u2.

We recommend that you upgrade your websvn packages.");
    script_tag(name: "summary",   value: "Nitin Venkatesh discovered 
that websvn, a web viewer for Subversion repositories, is susceptible to
cross-site scripting attacks via specially crafted file and directory names
in repositories.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"websvn", ver:"2.3.3-1.2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
