# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1341.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122446");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:45:31 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1341");
script_tag(name: "insight", value: "ELSA-2009-1341 -  cman security, bug fix, and enhancement update - [2.0.115-1]- RSA II fencing agent has been fixed.- Resolves: rhbz#493802[2.0.114-1]- local variable 'verbose_filename' referenced before assignment has been fixed- RSA II fencing agent has been fixed.- Resolves: rhbz#493802 rhbz#514758[2.0.113-1]- Limitations with 2-node fence_scsi are now properly documented in the man page.- Resolves: rhbz#512998[2.0.112-1]- The pexpect exception is now properly checked in fence agents.- Resolves: rhbz#501586[2.0.111-1]- cman_tool leave remove does now properly reduces quorum.- Resolves: rhbz#505258[2.0.110-1]- Updated fence_lpar man page to remove options that do not yet exist.- Resolves: rhbz#498045[2.0.108-1]- A semaphore leak in cman has been fixed.- Resolves: rhbz#505594[2.0.107-1]- Added man page for lpar fencing agent (fence_lpar). - Resolves: rhbz#498045[2.0.106-1]- The lssyscfg command can take longer than the shell timeout which will cause fencing to fail, we now wait longer for the lssyscfg command to complete.- Resolves: rhbz#504705[2.0.105-1]- The fencing agents no longer fail with pexpect exceptions.- Resolves: rhbz#501586[2.0.104-1]- Broadcast communcations are now possible with cman- fence_lpar can now login to IVM systems- Resolves: rhbz#502674 rhbz#492808[2.0.103-1]- fence_apc no longer fails with a pexpect exception- symlink vulnerabilities in fance_apc_snmp were fixed- The virsh fencing agent was added.- Resolves: rhbz#496629 rhbz#498952 rhbz#501586[2.0.102-1]- Correct return code is checked during disk scanning check.- Resolves: rhbz#484956[2.0.101-1]- The SCSI fence agent now verifies that sg_persist is installed properly.- The DRAC5 fencing agent now properly handles a modulename.- QDisk now logs warning messages if it appears it's I/O to shared storage is hung.- Resolves: rhbz#496724 rhbz#500450 rhbz#500567[2.0.100-1]- Support has been added for ePowerSwitch 8+ devices- cluster.conf files can now have more than 52 entries inside a block inside[block]- The output of the group_tool dump sub commands are no longer NULL padded.- Using device='' instead of label='' no longer causes qdiskd to incorrectly exit- The IPMI fencing agent has been modified to timeout after 10 seconds. It is also now possible to specify a different timeout with the '-t' option.- The IPMI fencing agent now allows punctuation in the password- Quickly starting and stopping the cman service no longer causes the cluster membership to become inconsistent across the cluster- An issue with lock syncing causing 'receive_own from ...' errors in syslog has been fixed- An issue which caused gfs_controld to segfault when mounting hundreds of filesystems has been fixed- The LPAR fencing agent now properly reports status when an LPAR is in Open Firmware- The APC SNMP fencing agent now properly recognizes outletStatusOn and outletStatusOff returns codes from the SNMP agent- WTI Fencing agent can now connect to fencing devices with no password- The rps-10 fencing agent now properly performs a reboot when run with no options.- The IPMI fencing agent now supports different cipher types with the '-C' option- Qdisk now properly scans devices and partitions- Added support for LPAR/HMC v3- cman now checks to see if a new node has state to prevent killing the first node during cluster setup- service qdiskd start now works properly- The McData fence agent now works properly with the Sphereon 4500 model- The Egenera fence agent can now specify an ssh login name- APC Fence agent works with non-admin accounts with firmware 3.5.x- fence_xvmd now tries two methods to reboot a virtual machine- Connections to openais are now allowed from unprivileged CPG clients with user and group of 'ais'- Support has been added for Cisco 9124/9134 SAN switches- groupd no longer allows the default fence domain to be '0' which would cause rgmanager to hang- The RSA fence agent now supports ssh enabled RSA II devices- DRAC fence agent now works with iDRAC on the Dell M600 Blade Chassis- fence_drac5 now shows proper usage instructions- cman no longer uses the wrong node name when getnameinfo() fails- The SCSI fence agent now verifies that sg_persist is installed properly- Resolves: rhbz#467112 rhbz#468966 rhbz#470318 rhbz#276541 rhbz#447964 rhbz#472786 rhbz#474163 rhbz#480401 rhbz#481566 rhbz#484095 rhbz#481664 rhbz#322291 rhbz#447497 rhbz#484956 rhbz#485700 rhbz#485026 rhbz#485199 rhbz#470983 rhbz#488958 rhbz#487501 rhbz#491640 rhbz#480178 rhbz#485469 rhbz#480836 rhbz#493207 rhbz#493802 rhbz#462390 rhbz#498329 rhbz#488565 rhbz#499871"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1341");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1341.html");
script_cve_id("CVE-2008-4579","CVE-2008-6552");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"cman", rpm:"cman~2.0.115~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"cman-devel", rpm:"cman-devel~2.0.115~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

