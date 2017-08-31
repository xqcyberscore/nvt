# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1385.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123070");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1385");
script_tag(name: "insight", value: "ELSA-2015-1385 -  net-snmp security and bug fix update - [1:5.5-54.0.1]- Add Oracle ACFS to hrStorage (John Haxby) [orabug 18510373][1:5.5-54]- Quicker loading of IP-MIB::ipAddrTable (#1191393)[1:5.5-53]- Quicker loading of IP-MIB::ipAddressTable (#1191393)[1:5.5-52]- Fixed snmptrapd crash when '-OQ' parameter is used and invalid trap is received (#CVE-2014-3565)[1:5.5-51]- added faster caching into IP-MIB::ipNetToMediaTable (#789500)- fixed compilation with '-Werror=format-security' (#1181994)- added clear error message when port specified in 'clientaddrr' config option cannot be bound (#886468)- fixed error check in IP-MIB::ipAddressTable (#1012430)- fixed agentx client crash on failed response (#1023570)- fixed dashes in net-snmp-config.h (#1034441)- fixed crash on monitor trigger (#1050970)- fixed 'netsnmp_assert 1 == new_val->high failed' message in system log (#1065210)- fixed parsing of 64bit counters from SMUX subagents (#1069046)- Fixed HOST-RESOURCES-MIB::hrProcessorTable on machines with >100 CPUs (#1070075)- fixed net-snmp-create-v3-user to have the same content on 32 and 64bit installations (#1073544)- fixed IPADDRESS value length in Python bindings (#1100099)- fixed hrStorageTable to contain 31 bits integers (#1104293)- fixed links to developer man pages (#1119567)- fixed storageUseNFS functionality in hrStorageTable (#1125793)- fixed netsnmp_set Python bindings call truncating at the first '\000' character (#1126914)- fixed log level of SMUX messages (#1140234)- use python/README to net-snmp-python subpackage (#1157373)- fixed forwarding of traps with RequestID=0 in snmptrapd (#1146948)- fixed typos in NET-SNMP-PASS-MIB and SMUX-MIB (#1162040)- fixed close() overhead of extend commands (#1188295)- fixed lmSensorsTable not reporting sensors with duplicate names (#967871)- fixed hrDeviceTable with interfaces with large ifIndex (#1195547)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1385");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1385.html");
script_cve_id("CVE-2014-3565");
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
  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.5~54.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.5~54.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.5~54.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.5~54.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.5~54.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.5~54.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

