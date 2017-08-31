# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0685.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122933");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-05-09 14:24:50 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0685");
script_tag(name: "insight", value: "ELSA-2016-0685 -  nss, nspr, nss-softokn, and nss-util security, bug fix, and enhancement update - nspr[4.11.0-1]- Rebase to NSPR 4.11nss[3.21.0-9.0.1]- Added nss-vendor.patch to change vendor[3.21.0-9]- Rebuild to require the latest nss-util build and nss-softokn build.[3.21.0-8]- Update the minimum nss-softokn build required at runtime.[3.21.0-7]- Delete duplicates from one table[3.21.0-6]- Fix missing support for sha384/dsa in certificate_request[3.21.0-5]- Fix the SigAlgs sent in certificate_request[3.21.0-4]- Ensure all ssl.sh tests are executed- Update sslauth test patch to run additional tests[3.21.0-2]- Fix sha384 support and testing patches[3.21.0-1]- Rebase to NSS-3.21- Resolves: Bug 1310581nss-softokn[3.16.2.3-14.2]- Adjust for a renamed variable in newer nss-util, require a compatible nss-util version.[3.16.2.3-14.1]- Pick up a bugfix related to fork(), to avoid a regression with NSS 3.21[3.16.2.3-14]- Pick up upstream freebl patch for CVE-2015-2730- Check for P == Q or P ==-Q before adding P and Qnss-util[3.21.0-2.2]- Rebase to nss-util from nss 3.21- Add aliases for naming compatibility with prior release"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0685");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0685.html");
script_cve_id("CVE-2016-1978","CVE-2016-1979");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.11.0~1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.11.0~1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.21.0~9.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.21.0~9.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.21.0~9.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.16.2.3~14.2.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.16.2.3~14.2.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.16.2.3~14.2.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.16.2.3~14.2.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.21.0~9.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.21.0~9.0.1.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.21.0~2.2.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.21.0~2.2.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

