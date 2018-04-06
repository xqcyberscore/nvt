# OpenVAS Vulnerability Test
# $Id: deb_3890.nasl 9356 2018-04-06 07:17:02Z cfischer $
# Auto-generated from advisory DSA 3890-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703890");
    script_version("$Revision: 9356 $");
    script_cve_id("CVE-2017-9736");
    script_name("Debian Security Advisory DSA 3890-1 (spip - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:17:02 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2017-06-21 00:00:00 +0200 (Wed, 21 Jun 2017)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2017/dsa-3890.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "spip on Debian Linux");
        script_tag(name: "insight",   value: "SPIP is a publishing system for the Internet in which great importance
is attached to collaborative working, to multilingual environments,
and to simplicity of use for web authors.");
    script_tag(name: "solution",  value: "For the stable distribution (stretch), this problem has been fixed in
version 3.1.4-3~deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 3.1.4-3.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.4-3.

We recommend that you upgrade your spip packages.");
    script_tag(name: "summary",   value: "Emeric Boit of ANSSI reported that SPIP, a website engine for
publishing, insufficiently sanitises the value from the X-Forwarded-Host
HTTP header field. An unauthenticated attacker can take advantage of
this flaw to cause remote code execution.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"spip", ver:"3.1.4-3", rls_regex:"DEB10.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spip", ver:"3.1.4-3~deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
