# OpenVAS Vulnerability Test
# $Id: deb_3684.nasl 8154 2017-12-18 07:30:14Z teissa $
# Auto-generated from advisory DSA 3684-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703684");
    script_version("$Revision: 8154 $");
    script_cve_id("CVE-2016-1246");
    script_name("Debian Security Advisory DSA 3684-1 (libdbd-mysql-perl - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-18 08:30:14 +0100 (Mon, 18 Dec 2017) $");
    script_tag(name:"creation_date", value:"2016-10-05 15:43:13 +0530 (Wed, 05 Oct 2016)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3684.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "libdbd-mysql-perl on Debian Linux");
    script_tag(name: "insight",   value: "DBD::mysql is the Perl5 Database
Interface driver for the MySQL database. In other words: DBD::mysql is an
interface between the Perl programming language and the MySQL programming API
that comes with the MySQL relational database management system. Most functions
provided by this programming API are supported. Some rarely used functions are
missing, mainly because noone ever requested them. However supported
features include: compression of data between server and client; timeouts;
SSL; prepared statement support; server administration such as creating
and dropping databases and restarting the server; auto-reconnection;
utf8; bind type guessing; bind comment placeholders; automated insert ids;
transactions; multiple result sets and multithreading.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
this problem has been fixed in version 4.028-2+deb8u2.

We recommend that you upgrade your libdbd-mysql-perl packages.");
    script_tag(name: "summary",   value: "Paul Rohar discovered that
libdbd-mysql-perl, the Perl DBI database driver for MySQL and MariaDB,
constructed an error message in a fixed-length buffer, leading to a crash
(_FORTIFY_SOURCE failure) and, potentially, to denial of service.");
    script_tag(name: "vuldetect", value: "This check tests the installed
software version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libdbd-mysql-perl", ver:"4.028-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
