# OpenVAS Vulnerability Test
# $Id: deb_3158.nasl 9355 2018-04-06 07:16:07Z cfischer $
# Auto-generated from advisory DSA 3158-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703158");
    script_version("$Revision: 9355 $");
    script_cve_id("CVE-2014-9274", "CVE-2014-9275");
    script_name("Debian Security Advisory DSA 3158-1 (unrtf - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:16:07 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2015-02-09 00:00:00 +0100 (Mon, 09 Feb 2015)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");

    script_xref(name: "URL", value: "http://www.debian.org/security/2015/dsa-3158.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "unrtf on Debian Linux");
    script_tag(name: "insight",   value: "UnRTF is a moderately complicated
converter from RTF to other formats, including HTML, LaTeX, and text.
Converting to HTML, it supports tables, fonts, colors, embedded images,
hyperlinks, paragraph alignment among other things. All other conversions
are 'alpha'--just begun.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
these problems have been fixed in version 0.21.5-3~deb7u1. This update is based
on a new upstream version of unrtf including additional bug fixes, new features
and incompatible changes (especially PostScript support is dropped).

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), these problems have been fixed in version 0.21.5-2.

We recommend that you upgrade your unrtf packages.");
    script_tag(name: "summary",   value: "Michal Zalewski and Hanno Boeck
discovered several vulnerabilities in unrtf, a RTF to other formats converter,
leading to a denial of service (application crash) or, potentially, the execution
of arbitrary code.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"unrtf", ver:"0.21.5-3~deb7u1", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
