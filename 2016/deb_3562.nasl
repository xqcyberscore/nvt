# OpenVAS Vulnerability Test
# $Id: deb_3562.nasl 8115 2017-12-14 07:30:22Z teissa $
# Auto-generated from advisory DSA 3562-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703562");
    script_version("$Revision: 8115 $");
    script_cve_id("CVE-2015-0857", "CVE-2015-0858");
    script_name("Debian Security Advisory DSA 3562-1 (tardiff - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-14 08:30:22 +0100 (Thu, 14 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-05-01 00:00:00 +0200 (Sun, 01 May 2016)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3562.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "tardiff on Debian Linux");
    script_tag(name: "insight",   value: "TarDiff compares the contents
of two tarballs and reports on any differences found between them. Its use
is mainly for release managers who can use it as a QA tool to make sure no
files have accidently been left over or were added by mistake. TarDiff supports
compressed tarballs, diff statistics and suppression of GNU autotool
changes.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
these problems have been fixed in version 0.1-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 0.1-5 and partially in earlier versions.

We recommend that you upgrade your tardiff packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities were discovered
in tardiff, a tarball comparison tool. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2015-0857 
Rainer Mueller and Florian Weimer discovered that tardiff is prone
to shell command injections via shell meta-characters in filenames
in tar files or via shell meta-characters in the tar filename
itself.

CVE-2015-0858 
Florian Weimer discovered that tardiff uses predictable temporary
directories for unpacking tarballs. A malicious user can use this
flaw to overwrite files with permissions of the user running the
tardiff command line tool.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"tardiff", ver:"0.1-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
