# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0591.nasl 5557 2017-03-13 10:00:29Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122919");
script_version("$Revision: 5557 $");
script_tag(name:"creation_date", value:"2016-04-06 14:32:59 +0300 (Wed, 06 Apr 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-03-13 11:00:29 +0100 (Mon, 13 Mar 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0591");
script_tag(name: "insight", value: "ELSA-2016-0591 -  nss, nss-util, and nspr security, bug fix, and enhancement update - nspr[4.11.0-0.1]- Rebase to NSPR 4.11nss[3.21.0-0.3.0.1]- Added nss-vendor.patch to change vendor[3.21.0-0.3]- Ensure all ssl.sh tests are executed[3.21.0-0.2]- Ensure abi compatibility[3.21.0-0.1]- Rebase to NSS-3.21nss-util[3.21.0-0.3]- Rebase RHEL 6.7.z to NSS-util 3.21 in preparation for Firefox 45- Resolves: Bug 1299874- Update upstream patch for CVE-2016-1950"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0591");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0591.html");
script_cve_id("CVE-2016-1978","CVE-2016-1979");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
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
  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.11.0~0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.11.0~0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.21.0~0.3.0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.21.0~0.3.0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.21.0~0.3.0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.21.0~0.3.0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.21.0~0.3.0.1.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.21.0~0.3.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.21.0~0.3.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

