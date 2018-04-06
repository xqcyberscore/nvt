# OpenVAS Vulnerability Test
# $Id: deb_2408_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2408-1 (php5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
tag_insight = "Several vulnerabilities have been discovered in PHP, the web scripting
language. The Common Vulnerabilities and Exposures project identifies
the following issues:

CVE-2011-1072

It was discoverd that insecure handling of temporary files in the PEAR
installer could lead to denial of service.

CVE-2011-4153

Maksymilian Arciemowicz discovered that a NULL pointer dereference in
the zend_strndup() function could lead to denial of service.

CVE-2012-0781

Maksymilian Arciemowicz discovered that a NULL pointer dereference in
the tidy_diagnose() function could lead to denial of service.

CVE-2012-0788

It was discovered that missing checks in the handling of PDORow
objects could lead to denial of service.

CVE-2012-0831

It was discovered that the magic_quotes_gpc setting could be disabled
remotely

This update also addresses PHP bugs, which are not treated as security issues
in Debian (see README.Debian.security), but which were fixed nonetheless:
CVE-2010-4697, CVE-2011-1092, CVE-2011-1148, CVE-2011-1464, CVE-2011-1467
CVE-2011-1468, CVE-2011-1469, CVE-2011-1470, CVE-2011-1657, CVE-2011-3182
CVE-2011-3267

For the stable distribution (squeeze), this problem has been fixed in
version 5.3.3-7+squeeze8.

For the unstable distribution (sid), this problem has been fixed in
version 5.3.10-1.

We recommend that you upgrade your php5 packages.";
tag_summary = "The remote host is missing an update to php5
announced via advisory DSA 2408-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202408-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71135");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-1072", "CVE-2011-4153", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0831", "CVE-2010-4697", "CVE-2011-1092", "CVE-2011-1148", "CVE-2011-1464", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1657", "CVE-2011-3182", "CVE-2011-3267");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:30:50 -0400 (Mon, 12 Mar 2012)");
 script_name("Debian Security Advisory DSA 2408-1 (php5)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");
res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.3.3-7+squeeze8", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
