# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0876.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123888");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:09:53 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0876");
script_tag(name: "insight", value: "ELSA-2012-0876 -  net-snmp security and bug fix update - [1:5.5-41]- moved /var/lib/net-snmp fro net-snmp to net-snmp-libs package (#822480)[1:5.5-40]- fixed CVE-2012-2141 (#820100)[1:5.5-39]- fixed proxying of out-of-tree GETNEXT requests (#799291)[1:5.5-38]- fixed snmpd crashing with many AgentX subagent (#749227)- fixed SNMPv2-MIB::sysObjectID value when sysObjectID config file option with long OID was used (#786931)- fixed value of BRIDGE-MIB::dot1dBasePortIfIndex.1 (#740172)- fixed parsing of proxy snmpd.conf option not to enable verbose logging by default (#746903)- added new realStorageUnits config file option to support disks > 16 TB in hrStorageTable (#741789)- added vxfs, reiserfs and ocfs2 filesystem support to hrStorageTable (#746903)- fixed snmpd sigsegv when embedded perl script registers one handler twice (#748907)- fixed setting of SNMP-TARGET-MIB::snmpTargetAddrRowStatus via SNMP-SET request on 64-bit platforms (#754275)- fixed crash when /var/lib/net-snmp/mib_indexes/ files have wrong SELinux context (#754971)- fixed memory leak when agentx subagent disconnects in the middle of request processing (#736580)- fixed slow (re-)loads of TCP-MIB::tcpConnectionTable (#789909)- removed 'error finding row index in _ifXTable_container_row_restore' error message (#788954)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0876");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0876.html");
script_cve_id("CVE-2012-2141");
script_tag(name:"cvss_base", value:"3.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.5~41.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.5~41.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.5~41.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.5~41.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.5~41.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.5~41.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

