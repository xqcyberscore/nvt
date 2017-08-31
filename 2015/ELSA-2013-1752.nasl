# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1752.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123519");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1752");
script_tag(name: "insight", value: "ELSA-2013-1752 -  389-ds-base security update - [1.2.11.15-30] - Resolves: bug 1024977 CVE-2013-4485 389-ds-base: DoS due to improper handling of ger attr searches [1.2.11.15-29] - Bump version to 1.2.11.15-29 - Resolves: bug 1008013: DS91: ns-slapd stuck in DS_Sleep [1.2.11.15-28] - Bump version to 1.2.11.15-28 - Resolves: Bug 1016038 - Users from AD sub OU does not sync to IPA (ticket 47488) [1.2.11.15-27] - Bump version to 1.2.11.15-27 - Resolves: Bug 1013735 - CLEANALLRUV doesnt run across all replicas (ticket 47509) [1.2.11.15-26] - Bump version to 1.2.11.15-26 - Resolves: Bug 947583 - ldapdelete returns non-leaf entry error while trying to remove a leaf entry (ticket 47534) [1.2.11.15-25] - Bump version to 1.2.11.15-25 - Resolves: Bug 1006846 - 2Master replication with SASL/GSSAPI auth broken (ticket 47523) - Resolves: Bug 1007452 - Under specific values of nsDS5ReplicaName, replication may get broken or updates (ticket 47489) [1.2.11.15-24] - Bump version to 1.2.11.15-24 - Resolves: Bug 982325 - Overflow in nsslapd-disk-monitoring-threshold; Changed CONFIG_INT to CONFIG_LONG for nsslapd-disk-monioring-threshold (ticket 47427) [1.2.11.15-23] - Bump version to 1.2.11.15-23 - Resolves: Bug 1000632 - CVE-2013-4283 389-ds-base: ns-slapd crash due to bogus DN - Resolves: Bug 1002260 - server fails to start after upgrade(schema error) (ticket 47318)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1752");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1752.html");
script_cve_id("CVE-2013-4485");
script_tag(name:"cvss_base", value:"4.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~30.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~30.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~30.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

