# OpenVAS Vulnerability Test
# $Id: deb_2534_1.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2534-1 using nvtgen 1.0
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

tag_affected  = "postgresql-8.4 on Debian Linux";
tag_insight   = "PostgreSQL is a fully featured object-relational database management
system. It supports a large part of the SQL standard and is designed
to be extensible by users in many aspects. Some of the features are:
ACID transactions, foreign keys, views, sequences, subqueries,
triggers, user-defined types and functions, outer joins, multiversion
concurrency control. Graphical user interfaces and bindings for many
programming languages are available as well.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed
in version 8.4.13-0squeeze1.

For the unstable distribution (sid), these problems have been fixed in
version 9.1.5-1 of the postgresql-9.1 package.

We recommend that you upgrade your postgresql-8.4 packages.";
tag_summary   = "Two vulnerabilities related to XML processing were discovered in
PostgreSQL, an SQL database.

CVE-2012-3488contrib/xml2's xslt_process() can be used to read and write
external files and URLs.

CVE-2012-3489xml_parse() fetches external files or URLs to resolve DTD and
entity references in XML values.

This update removes the problematic functionality, potentially
breaking applications which use it in a legitimate way.

Due to the nature of these vulnerabilities, it is possible that
attackers who have only indirect access to the database can supply
crafted XML data which exploits this vulnerability.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892534");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-3489", "CVE-2012-3488");
    script_name("Debian Security Advisory DSA 2534-1 (postgresql-8.4 - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name:"cvss_base", value:"4.9");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2534.html");


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
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-8.4", ver:"8.4.13-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
