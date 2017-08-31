# OpenVAS Vulnerability Test
# $Id: alas-2011-7.nasl 6579 2017-07-06 13:45:14Z cfischer $
 
# Description: Amazon Linux security check 
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
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.120517");
script_version("$Revision: 6579 $");
script_tag(name:"creation_date", value:"2015-09-08 11:27:40 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:45:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2011-7");
script_tag(name: "insight", value: "PHP before 5.3.7 does not properly check the return values of the malloc, calloc, and realloc library functions, which allows context-dependent attackers to cause a denial of service (NULL pointer dereference and application crash) or trigger a buffer overflow by leveraging the ability to provide an arbitrary value for a function argument, related to (1) ext/curl/interface.c, (2) ext/date/lib/parse_date.c, (3) ext/date/lib/parse_iso_intervals.c, (4) ext/date/lib/parse_tz.c, (5) ext/date/lib/timelib.c, (6) ext/pdo_odbc/pdo_odbc.c, (7) ext/reflection/php_reflection.c, (8) ext/soap/php_sdl.c, (9) ext/xmlrpc/libxmlrpc/base64.c, (10) TSRM/tsrm_win32.c, and (11) the strtotime function.The is_a function in PHP 5.3.7 and 5.3.8 triggers a call to the __autoload function, which makes it easier for remote attackers to execute arbitrary code by providing a crafted URL and leveraging potentially unsafe behavior in certain PEAR packages and custom autoloaders.php: changes to is_a() in 5.3.7 may allow arbitrary code execution with certain codeA signedness issue was found in the way the PHP crypt() function handled 8-bit characters in passwords when using Blowfish hashing. Up to three characters immediately preceding a non-ASCII character (one with the high bit set) had no effect on the hash result, thus shortening the effective password length. This made brute-force guessing more efficient as several different passwords were hashed to the same value.A signedness issue was found in the way the crypt() function in the PostgreSQL pgcrypto module handled 8-bit characters in passwords when using Blowfish hashing. Up to three characters immediately preceding a non-ASCII character (one with the high bit set) had no effect on the hash result, thus shortening the effective password length. This made brute-force guessing more efficient as several different passwords were hashed to the same value.crypt_blowfish before 1.1, as used in PHP before 5.3.7 on certain platforms, PostgreSQL before 8.4.9, and other products, does not properly handle 8-bit characters, which makes it easier for context-dependent attackers to determine a cleartext password by leveraging knowledge of a password hash.A stack-based buffer overflow flaw was found in the way the PHP socket extension handled long AF_UNIX socket addresses. An attacker able to make a PHP script connect to a long AF_UNIX socket address could use this flaw to crash the PHP interpreter.Stack-based buffer overflow in the socket_connect function in ext/sockets/sockets.c in PHP 5.3.3 through 5.3.6 might allow context-dependent attackers to execute arbitrary code via a long pathname for a UNIX socket.The rfc1867_post_handler function in main/rfc1867.c in PHP before 5.3.7 does not properly restrict filenames in multipart/form-data POST requests, which allows remote attackers to conduct absolute path traversal attacks, and possibly create or overwrite arbitrary files, via a crafted upload request, related to a file path injection vulnerability.An off-by-one flaw was found in PHP. If an attacker uploaded a file with a specially-crafted file name it could cause a PHP script to attempt to write a file to the root (/) directory. By default, PHP runs as the apache user, preventing it from writing to the root directory.The rfc1867_post_handler function in main/rfc1867.c in PHP before 5.3.7 does not properly restrict filenames in multipart/form-data POST requests, which allows remote attackers to conduct absolute path traversal attacks, and possibly create or overwrite arbitrary files, via a crafted upload request, related to a 'file path injection vulnerability.'Use-after-free vulnerability in the substr_replace function in PHP 5.3.6 and earlier allows context-dependent attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact by using the same variable for multiple arguments.A use-after-free flaw was found in the PHP substr_replace() function. If a PHP script used the same variable as multiple function arguments, a remote attacker could possibly use this to crash the PHP interpreter or, possibly, execute arbitrary code."); 
script_tag(name : "solution", value : "Run yum update php to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2011-7.html");
script_cve_id("CVE-2011-3182", "CVE-2011-3379", "CVE-2011-2483", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-1148");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-mssql", rpm:"php-mssql~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php", rpm:"php~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-zts", rpm:"php-zts~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~5.3.8~3.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
