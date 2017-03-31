# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-394.nasl 4514 2016-11-15 10:04:28Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120246");
script_version("$Revision: 4514 $");
script_tag(name:"creation_date", value:"2015-09-08 13:21:17 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 11:04:28 +0100 (Tue, 15 Nov 2016) $");
script_name("Amazon Linux Local Check: ALAS-2014-394");
script_tag(name: "insight", value: "The implementation of the ORDER BY SQL statement in Zend_Db_Select of Zend Framework 1 contains a potential SQL injection when the query string passed contains parentheses, as discussed in http://framework.zend.com/security/advisory/ZF2014-04."); 
script_tag(name : "solution", value : "Run yum update php-ZendFramework to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-394.html");
script_cve_id("CVE-2014-4914");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("HostDetails/OS/cpe:/o:amazon:linux", "login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_summary("Amazon Linux Local Security Checks ALAS-2014-394");
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
if ((res = isrpmvuln(pkg:"php-ZendFramework-Serializer-Adapter-Igbinary", rpm:"php-ZendFramework-Serializer-Adapter-Igbinary~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-full", rpm:"php-ZendFramework-full~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Mysql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Mysql~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Dojo", rpm:"php-ZendFramework-Dojo~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo", rpm:"php-ZendFramework-Db-Adapter-Pdo~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Pdf", rpm:"php-ZendFramework-Pdf~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Services", rpm:"php-ZendFramework-Services~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Search-Lucene", rpm:"php-ZendFramework-Search-Lucene~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Libmemcached", rpm:"php-ZendFramework-Cache-Backend-Libmemcached~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework", rpm:"php-ZendFramework~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Apc", rpm:"php-ZendFramework-Cache-Backend-Apc~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-demos", rpm:"php-ZendFramework-demos~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Soap", rpm:"php-ZendFramework-Soap~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Mysqli", rpm:"php-ZendFramework-Db-Adapter-Mysqli~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Ldap", rpm:"php-ZendFramework-Ldap~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-extras", rpm:"php-ZendFramework-extras~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Pgsql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Pgsql~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Captcha", rpm:"php-ZendFramework-Captcha~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Mssql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Mssql~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Feed", rpm:"php-ZendFramework-Feed~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Auth-Adapter-Ldap", rpm:"php-ZendFramework-Auth-Adapter-Ldap~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Memcached", rpm:"php-ZendFramework-Cache-Backend-Memcached~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"php-ZendFramework", rpm:"php-ZendFramework~1.12.7~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
