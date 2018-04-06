# OpenVAS Vulnerability Test
# $Id: deb_2801.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2801-1 using nvtgen 1.0
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

tag_affected  = "libhttp-body-perl on Debian Linux";
tag_insight   = "HTTP::Body is a Perl module for manipulating HTTP POST request data in an
object-oriented way, providing support for application/x-www-form-urlencoded
application/octet-stream, and multipart/form-data.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 1.11-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.17-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.17-2.

We recommend that you upgrade your libhttp-body-perl packages.";
tag_summary   = "Jonathan Dolle reported a design error in HTTP::Body, a Perl module for
processing data from HTTP POST requests. The HTTP body multipart parser
creates temporary files which preserve the suffix of the uploaded file.
An attacker able to upload files to a service that uses
HTTP::Body::Multipart could potentially execute commands on the server
if these temporary filenames are used in subsequent commands without
further checks.

This update restricts the possible suffixes used for the created
temporary files.

The oldstable distribution (squeeze) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892801");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-4407");
    script_name("Debian Security Advisory DSA 2801-1 (libhttp-body-perl - design error)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-11-21 00:00:00 +0100 (Thu, 21 Nov 2013)");
    script_tag(name: "cvss_base", value:"6.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2801.html");


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
if ((res = isdpkgvuln(pkg:"libhttp-body-perl", ver:"1.11-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
