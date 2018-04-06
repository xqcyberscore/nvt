# OpenVAS Vulnerability Test
# $Id: deb_2633.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2633-1 using nvtgen 1.0
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

tag_affected  = "fusionforge on Debian Linux";
tag_insight   = "FusionForge provides many tools to aid collaboration in a
development project, such as bug-tracking, task management,
mailing-lists, SCM repository, forums, support request helper,
web/FTP hosting, release management, etc. All these services are
integrated into one web site and managed through a web interface.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 5.0.2-5+squeeze2.

For the testing (wheezy) and unstable (sid) distribution, these problems will
be fixed soon.

We recommend that you upgrade your fusionforge packages.";
tag_summary   = "Helmut Grohne discovered multiple privilege escalation flaws in FusionForge, a
web-based project-management and collaboration software. Most of the
vulnerabilities are related to the bad handling of privileged operations on
user-controlled files or directories.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892633");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1423");
    script_name("Debian Security Advisory DSA 2633-1 (fusionforge - privilege escalation)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-02-26 00:00:00 +0100 (Tue, 26 Feb 2013)");
    script_tag(name: "cvss_base", value:"6.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2633.html");


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
if ((res = isdpkgvuln(pkg:"fusionforge-full", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fusionforge-minimal", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fusionforge-standard", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-common", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-courier", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-contribtracker", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-extratabs", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-globalsearch", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-mediawiki", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-projectlabels", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmarch", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmbzr", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmcvs", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmdarcs", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmgit", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmhg", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmsvn", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-web-apache", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-web-apache2", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-web-apache2-vhosts", ver:"5.0.2-5+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
