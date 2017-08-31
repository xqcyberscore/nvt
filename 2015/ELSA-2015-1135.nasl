# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1135.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123097");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:19 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1135");
script_tag(name: "insight", value: "ELSA-2015-1135 -  php security and bug fix update - [5.4.16-36]- fix more functions accept paths with NUL character #1213407[5.4.16-35]- core: fix multipart/form-data request can use excessive amount of CPU usage CVE-2015-4024- fix various functions accept paths with NUL character CVE-2015-4025, CVE-2015-4026, #1213407- fileinfo: fix denial of service when processing a crafted file #1213442- ftp: fix integer overflow leading to heap overflow when reading FTP file listing CVE-2015-4022- phar: fix buffer over-read in metadata parsing CVE-2015-2783- phar: invalid pointer free() in phar_tar_process_metadata() CVE-2015-3307- phar: fix buffer overflow in phar_set_inode() CVE-2015-3329- phar: fix memory corruption in phar_parse_tarfile caused by empty entry file name CVE-2015-4021- soap: fix type confusion through unserialize #1222538- apache2handler: fix pipelined request executed in deinitialized interpreter under httpd 2.4 CVE-2015-3330[5.4.16-34]- fix memory corruption in fileinfo module on big endian machines #1082624- fix segfault in pdo_odbc on x86_64 #1159892- fix segfault in gmp allocator #1154760[5.4.16-33]- core: use after free vulnerability in unserialize() CVE-2014-8142 and CVE-2015-0231- core: fix use-after-free in unserialize CVE-2015-2787- core: fix NUL byte injection in file name argument of move_uploaded_file() CVE-2015-2348- date: use after free vulnerability in unserialize CVE-2015-0273- enchant: fix heap buffer overflow in enchant_broker_request_dict CVE-2014-9705- exif: free called on unitialized pointer CVE-2015-0232- fileinfo: fix out of bounds read in mconvert CVE-2014-9652- gd: fix buffer read overflow in gd_gif_in.c CVE-2014-9709- phar: use after free in phar_object.c CVE-2015-2301- soap: fix type confusion through unserialize[5.4.16-31]- fileinfo: fix out-of-bounds read in elf note headers. CVE-2014-3710[5.4.16-29]- xmlrpc: fix out-of-bounds read flaw in mkgmtime() CVE-2014-3668- core: fix integer overflow in unserialize() CVE-2014-3669- exif: fix heap corruption issue in exif_thumbnail() CVE-2014-3670[5.4.16-27]- gd: fix NULL pointer dereference in gdImageCreateFromXpm(). CVE-2014-2497- gd: fix NUL byte injection in file names. CVE-2014-5120- fileinfo: fix extensive backtracking in regular expression (incomplete fix for CVE-2013-7345). CVE-2014-3538- fileinfo: fix mconvert incorrect handling of truncated pascal string size. CVE-2014-3478- fileinfo: fix cdf_read_property_info (incomplete fix for CVE-2012-1571). CVE-2014-3587- spl: fix use-after-free in ArrayIterator due to object change during sorting. CVE-2014-4698- spl: fix use-after-free in SPL Iterators. CVE-2014-4670- network: fix segfault in dns_get_record (incomplete fix for CVE-2014-4049). CVE-2014-3597[5.4.16-25]- fix segfault after startup on aarch64 (#1107567)- compile php with -O3 on ppc64le (#1123499)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1135");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1135.html");
script_cve_id("CVE-2014-8142","CVE-2014-9652","CVE-2014-9705","CVE-2014-9709","CVE-2015-0231","CVE-2015-0232","CVE-2015-0273","CVE-2015-2301","CVE-2015-2348","CVE-2015-2783","CVE-2015-2787","CVE-2015-3307","CVE-2015-3329","CVE-2015-3330","CVE-2015-3411","CVE-2015-3412","CVE-2015-4021","CVE-2015-4022","CVE-2015-4024","CVE-2015-4025","CVE-2015-4026","CVE-2015-4147","CVE-2015-4148","CVE-2015-4598","CVE-2015-4599","CVE-2015-4600","CVE-2015-4601","CVE-2015-4602","CVE-2015-4603","CVE-2015-4604","CVE-2015-4605");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.4.16~36.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

