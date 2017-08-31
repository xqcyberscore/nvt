# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1335.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122445");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:45:30 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1335");
script_tag(name: "insight", value: "ELSA-2009-1335 -  openssl security, bug fix, and enhancement update - [0.9.8e-12]- abort if selftests failed and random number generator is polled- mention EVP_aes and EVP_sha2xx routines in the manpages- add README.FIPS[0.9.8e-10]- fix CVE-2009-1386 CVE-2009-1387 (DTLS DoS problems) (#503685, #503688)[0.9.8e-9]- fix CVE-2009-1377 CVE-2009-1378 CVE-2009-1379 (DTLS DoS problems) (#501253, #501254, #501572)[0.9.8e-8]- support multiple CRLs with same subject in a store (#457134)- fix CVE-2009-0590 - reject incorrectly encoded ASN.1 strings (#492304)- seed FIPS rng directly from kernel random device- do not require fipscheck to build the package (#475798)- call pairwise key tests in FIPS mode only (#479817)- do not crash when parsing bad mime data (#472440)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1335");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1335.html");
script_cve_id("CVE-2009-0590","CVE-2009-1377","CVE-2009-1378","CVE-2009-1379","CVE-2009-1386","CVE-2009-1387","CVE-2006-7250");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

