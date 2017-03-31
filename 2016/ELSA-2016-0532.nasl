# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0532.nasl 5557 2017-03-13 10:00:29Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122923");
script_version("$Revision: 5557 $");
script_tag(name:"creation_date", value:"2016-04-06 14:33:01 +0300 (Wed, 06 Apr 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-03-13 11:00:29 +0100 (Mon, 13 Mar 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0532");
script_tag(name: "insight", value: "ELSA-2016-0532 -  krb5 security update - [1.13.2-12]- Fix CVE-2015-8631, CVE-2015-8630, and CVE-2015-8629- Remove obsolete trigger to enable building of package- Resolves: #1306969"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0532");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0532.html");
script_cve_id("CVE-2015-8629","CVE-2015-8631","CVE-2015-8630");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.13.2~12.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.13.2~12.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.13.2~12.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.13.2~12.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.13.2~12.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.13.2~12.el7_2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

