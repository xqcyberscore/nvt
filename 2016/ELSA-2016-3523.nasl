# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-3523.nasl 8842 2018-02-16 09:52:40Z asteins $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.fi
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.122888");
script_version("$Revision: 8842 $");
script_tag(name:"creation_date", value:"2016-03-02 06:56:05 +0200 (Wed, 02 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2018-02-16 10:52:40 +0100 (Fri, 16 Feb 2018) $");
script_name("Oracle Linux Local Check: ELSA-2016-3523");
script_tag(name: "insight", value: "ELSA-2016-3523 -  openssl security update - [1.0.1e-51.4]- fix CVE-2016-0702 - side channel attack on modular exponentiation- fix CVE-2016-0705 - double-free in DSA private key parsing- fix CVE-2016-0797 - heap corruption in BN_hex2bn and BN_dec2bn[1.0.1e-51.3]- fix CVE-2015-3197 - SSLv2 ciphersuite enforcement- disable SSLv2 in the generic TLS method[1.0.1e-51.2]- fix CVE-2015-7575 - disallow use of MD5 in TLS1.2[1.0.1e-51.1]- fix CVE-2015-3194 - certificate verify crash with missing PSS parameter- fix CVE-2015-3195 - X509_ATTRIBUTE memory leak- fix CVE-2015-3196 - race condition when handling PSK identity hint"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-3523");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-3523.html");
script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2015-3197", "CVE-2015-7575", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
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
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

