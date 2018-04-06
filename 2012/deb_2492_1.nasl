# OpenVAS Vulnerability Test
# $Id: deb_2492_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2492-1 (php5)
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
tag_insight = "The Phar extension for PHP does not properly handle crafted tar files,
leading to a heap-based buffer overflow.  PHP applications processing
tar files could crash or, potentially, execute arbitrary code.

In addition, this update addresses a regression which caused a crash
when accessing a global object that is returned as $this from __get.

For the stable distribution (squeeze), this problem has been fixed in
version 5.3.3-7+squeeze13.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 5.4.4~rc1-1.

We recommend that you upgrade your php5 packages.";
tag_summary = "The remote host is missing an update to php5
announced via advisory DSA 2492-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202492-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71470");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2386");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:04:50 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2492-1 (php5)");



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
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.3.3-7+squeeze13", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
