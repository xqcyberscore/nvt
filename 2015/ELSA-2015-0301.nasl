# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0301.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123174");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:19 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0301");
script_tag(name: "insight", value: "ELSA-2015-0301 -  hivex security, bug fix, and enhancement update - [1.3.10-5.7]- Fix: 'Argument list too long' when using virt-v2v on Windows guest with French copy of Citrix installed related: rhbz#1145056[1.3.10-5.6]- Fix: typo in man page resolves: rhbz#1099286[1.3.10-5.4]- Fix: hivex missing checks for small/truncated files resolves: rhbz#1158992[1.3.10-5.3]- Fix: hivexml generates 'Argument list too long' error. resolves: rhbz#1145056[1.3.10-5.2]- Resolves: rhbz#1125544[1.3.10-5.1]- Rebase to hivex 1.3.10. resolves: rhbz#1023978"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0301");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0301.html");
script_cve_id("CVE-2014-9273");
script_tag(name:"cvss_base", value:"4.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"hivex", rpm:"hivex~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"hivex-devel", rpm:"hivex-devel~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocaml-hivex", rpm:"ocaml-hivex~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocaml-hivex-devel", rpm:"ocaml-hivex-devel~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perl-hivex", rpm:"perl-hivex~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-hivex", rpm:"python-hivex~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-hivex", rpm:"ruby-hivex~1.3.10~5.7.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

