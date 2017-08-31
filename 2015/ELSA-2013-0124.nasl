# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0124.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123759");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:09 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0124");
script_tag(name: "insight", value: "ELSA-2013-0124 -  net-snmp security and bug fix update - [5.3.2.2-20.0.2.el5] - snmptrapd: Fix crash due to access of freed memory (John Haxby) [orabug 14391194] [5.3.2.2-20.0.1.el5] - suppress spurious asserts on 32bit [Greg Marsden] [5.3.2.2-20] - fixed error message when the address specified by clientaddr option is wrong or cannot be bound (#840861) [5.3.2.2-19] - fixed support for port numbers in 'clientaddr' configuration option (#840861, #845974) - added support of cvfs filesystem hrStorageTable (#846391) - removed various error log messages when IPv6 is disabled (#845155) - removed various error log messages related to counte64 expansions (#846905) [5.3.2.2-18] - added support of ocfs2, tmpfs and reiserfs in hrStorageTable (#754652, #755958, #822061) - updated documentation of '-c' option of snmptrapd (#760001) - fixed endless loop after truncating 64bit int (#783892) - fixed snmpd exiting shortly after startup due to incoming signal (#799699) - fixed decoding of COUNTER64 values from AgentX (#803585) - fixed engineID of outgoing traps if 'trapsess -e ' is used in snmpd.conf (#805689) - fixed CVE-2012-2141, an array index error in the extension table (#815813) - fixed snmpd showing 'failed to run mteTrigger query' when 'monitor' config option is used (#830042) - added support for port numbers in 'clientaddr' configuration option (#828691)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0124");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0124.html");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.2.2~20.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.2.2~20.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.3.2.2~20.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.3.2.2~20.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.3.2.2~20.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

