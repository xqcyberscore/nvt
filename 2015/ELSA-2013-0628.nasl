# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0628.nasl 6600 2017-07-07 09:58:31Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123669");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0628");
script_tag(name: "insight", value: "ELSA-2013-0628 -  389-ds-base security and bug fix update - [1.2.11.15-12]- Resolves: Bug 910994 - PamConfig schema not updated during upgrade- Resolves: Bug 910995 - Valgrind reports memleak in modify_update_last_modified_attr- Resolves: Bug 910996 - DS returns error 20 when replacing values of a multi-valued attribute (only when replication is enabled)- Resolves: Bug 911467 - DNA: use event queue for config update only at the start up- Resolves: Bug 911468 - Error messages encountered when using POSIX winsync- Resolves: Bug 911469 - dse.ldif is 0 length after server kill or machine kill- Resolves: Bug 911474 - Invalid chaining config triggers a disk full error and shutdown- Resolves: Bug 914305 - ns-slapd segfaults while trying to delete a tombstone entry- Resolves: Bug 913228 - unauthenticated denial of service vulnerability in handling of LDAPv3 control data"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0628");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0628.html");
script_cve_id("CVE-2013-0312");
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
  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~12.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~12.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~12.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

