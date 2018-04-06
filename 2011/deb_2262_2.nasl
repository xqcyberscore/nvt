# OpenVAS Vulnerability Test
# $Id: deb_2262_2.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2262-2 (php5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The update for CVE-2010-2531 for the old stabledistribution (lenny)
introduced a regression, which lead to additional output being written
to stdout.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.2.6.dfsg.1-1+lenny13.

We recommend that you upgrade your php5 packages.";
tag_summary = "The remote host is missing an update to php5
announced via advisory DSA 2262-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202262-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69976");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2531", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0708", "CVE-2011-1153", "CVE-2011-1466", "CVE-2011-1471", "CVE-2011-2202");
 script_name("Debian Security Advisory DSA 2262-2 (php5)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-imap", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.6.dfsg.1-1+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
