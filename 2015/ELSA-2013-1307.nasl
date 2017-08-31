# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1307.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.123562");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:34 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1307");
script_tag(name: "insight", value: "ELSA-2013-1307 -  php53 security, bug fix and enhancement update - [5.3.3-21] - add security fix for CVE-2013-4248 [5.3.3-20] - add security fix for CVE-2013-4113 [5.3.3-19] - add upstream reproducer for error_handler (#951075) [5.3.3-18] - add security fixes for CVE-2006-7243 [5.3.3-17] - reorder security patches - add security fixes for CVE-2012-2688, CVE-2012-0831, CVE-2011-1398, CVE-2013-1643 [5.3.3-15] - fix segfault in error_handler with allow_call_time_pass_reference = Off (#951075) - fix double free when destroy_zend_class fails (#951076) [5.3.3-14] - fix possible buffer overflow in pdo_odbc (#869694) - rename php-5.3.3-extrglob.patch and reorder - php script hangs when it exceeds max_execution_time when inside an ODBC call (#864954) - fix zend garbage collector (#892695) - fix transposed memset arguments in libzip (#953818) - fix possible segfault in pdo_mysql (#869693) - fix imap_open DISABLE_AUTHENTICATOR param ignores array (#859369) - fix stream support in fileinfo (#869697) - fix setDate when DateTime created from timestamp (#869691) - fix permission on source files (#869688) - add php(language) and missing provides (#837044) - fix copy doesn't report failure on partial copy (#951413)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1307");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1307.html");
script_cve_id("CVE-2011-1398","CVE-2012-0831","CVE-2012-2688","CVE-2006-7243","CVE-2013-1643","CVE-2013-4248");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

