# OpenVAS Vulnerability Test
# $Id: deb_2961.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2961-1 using nvtgen 1.0
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

tag_affected  = "php5 on Debian Linux";
tag_insight   = "This package is a metapackage that, when installed, guarantees that you
have at least one of the four server-side versions of the PHP5 interpreter
installed. Removing this package won't remove PHP5 from your system, however
it may remove other packages that depend on this one.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 5.4.4-14+deb7u11.

For the testing distribution (jessie), this problem has been fixed in
version 5.6.0~beta4+dfsg-3.

For the unstable distribution (sid), this problem has been fixed in
version 5.6.0~beta4+dfsg-3.

We recommend that you upgrade your php5 packages.";
tag_summary   = "It was discovered that PHP, a general-purpose scripting language
commonly used for web application development, is vulnerable to a
heap-based buffer overflow in the DNS TXT record parsing. A malicious
server or man-in-the-middle attacker could possibly use this flaw to
execute arbitrary code as the PHP interpreter if a PHP application uses
dns_get_record() to perform a DNS query.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702961");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-4049");
    script_name("Debian Security Advisory DSA 2961-1 (php5 - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-06-16 00:00:00 +0200 (Mon, 16 Jun 2014)");
    script_tag(name:"cvss_base", value:"5.1");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2961.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
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

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.4-14+deb7u11", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.4-14+deb7u11", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.4-14+deb7u11", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php-pear", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-common", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.4-14+deb7u11", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
