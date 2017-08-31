# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0677.nasl 6600 2017-07-07 09:58:31Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122167");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:09 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0677");
script_tag(name: "insight", value: "ELSA-2011-0677 -  openssl security, bug fix, and enhancement update - [1.0.0-10]- fix OCSP stapling vulnerability - CVE-2011-0014 (#676063)- correct the README.FIPS document[1.0.0-8]- add -x931 parameter to openssl genrsa command to use the ANSI X9.31 key generation method- use FIPS-186-3 method for DSA parameter generation- add OPENSSL_FIPS_NON_APPROVED_MD5_ALLOW environment variable to allow using MD5 when the system is in the maintenance state even if the /proc fips flag is on- make openssl pkcs12 command work by default in the FIPS mode[1.0.0-7]- listen on ipv6 wildcard in s_server so we accept connections from both ipv4 and ipv6 (#601612)- fix openssl speed command so it can be used in the FIPS mode with FIPS allowed ciphers (#619762)[1.0.0-6]- disable code for SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG - CVE-2010-3864 (#649304)[1.0.0-5]- fix race in extension parsing code - CVE-2010-3864 (#649304)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0677");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0677.html");
script_cve_id("CVE-2011-0014");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.0~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.0~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.0~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.0~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

