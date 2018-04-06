# OpenVAS Vulnerability Test
# $Id: deb_3059.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 3059-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703059");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-8761", "CVE-2014-8762", "CVE-2014-8763", "CVE-2014-8764");
    script_name("Debian Security Advisory DSA 3059-1 (dokuwiki - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-10-29 00:00:00 +0100 (Wed, 29 Oct 2014)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3059.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "dokuwiki on Debian Linux");
        script_tag(name: "insight",   value: "DokuWiki is a wiki mainly aimed at creating documentation of any kind.
It is targeted at developer teams, workgroups and small companies. It
has a simple but powerful syntax which makes sure the datafiles remain
readable outside the wiki and eases the creation of structured texts.
All data is stored in plain text files -- no database is required.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy), these problems have been fixed in
version 0.0.20120125b-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 0.0.20140929.a-1.

We recommend that you upgrade your dokuwiki packages.");
    script_tag(name: "summary",   value: "Two vulnerabilities have been discovered in dokuwiki. Access control in
the media manager was insufficiently restricted and authentication could
be bypassed when using Active Directory for LDAP authentication.");
    script_tag(name: "vuldetect", value:  "This check tests the installed software version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"dokuwiki", ver:"0.0.20120125b-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dokuwiki", ver:"0.0.20120125b-2+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dokuwiki", ver:"0.0.20120125b-2+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dokuwiki", ver:"0.0.20120125b-2+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
