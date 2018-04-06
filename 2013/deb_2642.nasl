# OpenVAS Vulnerability Test
# $Id: deb_2642.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2642-1 using nvtgen 1.0
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

tag_affected  = "sudo on Debian Linux";
tag_insight   = "Sudo is a program designed to allow a sysadmin to give limited root
privileges to users and log root activity. The basic philosophy is to give
as few privileges as possible but still allow people to get their work done.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 1.7.4p4-2.squeeze.4.

For the testing (wheezy) and unstable (sid) distributions, these problems
have been fixed in version 1.8.5p2-1+nmu1.

We recommend that you upgrade your sudo packages.";
tag_summary   = "Several vulnerabilities have been discovered in sudo, a program designed
to allow a sysadmin to give limited root privileges to users. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1775 
Marco Schoepl discovered an authentication bypass when the clock is
set to the UNIX epoch [00:00:00 UTC on 1 January 1970].

CVE-2013-1776 
Ryan Castellucci and James Ogden discovered aspects of an issue that
would allow session id hijacking from another authorized tty.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892642");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1775", "CVE-2013-2777", "CVE-2013-2776", "CVE-2013-1776");
    script_name("Debian Security Advisory DSA 2642-1 (sudo - several issues)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-03-09 00:00:00 +0100 (Sat, 09 Mar 2013)");
    script_tag(name: "cvss_base", value:"6.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2642.html");


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
if ((res = isdpkgvuln(pkg:"sudo", ver:"1.7.4p4-2.squeeze.4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.7.4p4-2.squeeze.4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sudo", ver:"1.8.5p2-1+nmu1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.5p2-1+nmu1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
