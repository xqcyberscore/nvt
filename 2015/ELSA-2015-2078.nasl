# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2078.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122734");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-19 07:51:08 +0200 (Thu, 19 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2078");
script_tag(name: "insight", value: "ELSA-2015-2078 -  postgresql security update - [9.2.14-1]- update to 9.2.14 per release notes http://www.postgresql.org/docs/9.2/static/release-9-2-14.html[9.2.13-1]- update to 9.2.13 per release notes http://www.postgresql.org/docs/9.2/static/release-9-2-13.html[9.2.12-1]- update to 9.2.12 per release notes http://www.postgresql.org/docs/9.2/static/release-9-2-12.html[9.2.11-1]- update to 9.2.11 per release notes http://www.postgresql.org/docs/9.2/static/release-9-2-11.html"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2078");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2078.html");
script_cve_id("CVE-2015-5288","CVE-2015-5289");
script_tag(name:"cvss_base", value:"6.4");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"postgresql-upgrade", rpm:"postgresql-upgrade~9.2.14~1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

