# OpenVAS Vulnerability Test
# $Id: deb_3570.nasl 8168 2017-12-19 07:30:15Z teissa $
# Auto-generated from advisory DSA 3570-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703570");
    script_version("$Revision: 8168 $");
    script_cve_id("CVE-2016-3105");
    script_name("Debian Security Advisory DSA 3570-1 (mercurial - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-05-05 00:00:00 +0200 (Thu, 05 May 2016)");
    script_tag(name:"cvss_base", value:"6.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3570.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "mercurial on Debian Linux");
    script_tag(name: "insight",   value: "Mercurial is a fast, lightweight Source
Control Management system designed for efficient handling of very large distributed
projects...
Its features include:

* O(1) delta-compressed file storage and retrieval scheme
* Complete cross-indexing of files and changesets for efficient exploration
of project history
* Robust SHA1-based integrity checking and append-only storage model
* Decentralized development model with arbitrary merging between trees
* High-speed HTTP-based network merge protocol
* Easy-to-use command-line interface
* Integrated stand-alone web interface
* Small Python codebase");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
this problem has been fixed in version 3.1.2-2+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 3.8.1-1.

We recommend that you upgrade your mercurial packages.");
    script_tag(name: "summary",   value: "Blake Burkhart discovered an arbitrary
code execution flaw in Mercurial, a distributed version control system, when
using the convert extension on Git repositories with specially crafted names.
This flaw in particular affects automated code conversion services that allow
arbitrary repository names.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"mercurial", ver:"3.1.2-2+deb8u3", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mercurial-common", ver:"3.1.2-2+deb8u3", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
