###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2015-584.nasl 6575 2017-07-06 13:42:08Z cfischer$
#
# Amazon Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@iki.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120509");
  script_version("$Revision: 14117 $");
  script_tag(name:"creation_date", value:"2015-09-08 13:28:14 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_name("Amazon Linux Local Check: alas-2015-584");
  script_tag(name:"insight", value:"PHP process crashes when processing an invalid file with the phar extension. 
  (CVE-2015-5589)

  As discussed upstream, mysqlnd is vulnerable to the attack described in the references. (CVE-2015-3152)

  PHP versions before 5.5.27 and 5.4.43 contain buffer overflow issue. (CVE-2015-5590)");
  script_tag(name:"solution", value:"Run yum update php55 to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-584.html");
  script_xref(name:"URL", value:"https://www.duosecurity.com/blog/backronym-mysql-vulnerability");
  script_cve_id("CVE-2015-5589", "CVE-2015-3152", "CVE-2015-5590");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
  script_copyright("Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"php55-imap", rpm:"php55-imap~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-tidy", rpm:"php55-tidy~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-gd", rpm:"php55-gd~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-enchant", rpm:"php55-enchant~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-xmlrpc", rpm:"php55-xmlrpc~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-debuginfo", rpm:"php55-debuginfo~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-snmp", rpm:"php55-snmp~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-mbstring", rpm:"php55-mbstring~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55", rpm:"php55~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-dba", rpm:"php55-dba~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-embedded", rpm:"php55-embedded~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-common", rpm:"php55-common~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-process", rpm:"php55-process~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-pspell", rpm:"php55-pspell~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-soap", rpm:"php55-soap~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-odbc", rpm:"php55-odbc~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-mysqlnd", rpm:"php55-mysqlnd~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-gmp", rpm:"php55-gmp~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-fpm", rpm:"php55-fpm~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-intl", rpm:"php55-intl~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-ldap", rpm:"php55-ldap~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-pgsql", rpm:"php55-pgsql~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-devel", rpm:"php55-devel~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-cli", rpm:"php55-cli~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-mcrypt", rpm:"php55-mcrypt~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-xml", rpm:"php55-xml~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-bcmath", rpm:"php55-bcmath~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-opcache", rpm:"php55-opcache~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-recode", rpm:"php55-recode~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-mssql", rpm:"php55-mssql~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php55-pdo", rpm:"php55-pdo~5.5.28~1.106.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
