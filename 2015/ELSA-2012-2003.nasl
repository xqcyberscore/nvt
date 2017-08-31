# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-2003.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123956");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:48 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-2003");
script_tag(name: "insight", value: "ELSA-2012-2003 -  Unbreakable Enterprise kernel security and bug fix update - [2.6.32-300.11.1.el6uek]- [fs] xfs: Fix possible memory corruption in xfs_readlink (Carlos Maiolino) {CVE-2011-4077}- [scsi] increase qla2xxx firmware ready time-out (Joe Jin)- [scsi] qla2xxx: Module parameter to control use of async or sync port login (Joe Jin)- [net] tg3: Fix single-vector MSI-X code (Joe Jin)- [net] qlge: fix size of external list for TX address descriptors (Joe Jin)- [net] e1000e: Avoid wrong check on TX hang (Joe Jin)- crypto: ghash - Avoid null pointer dereference if no key is set (Nick Bowler) {CVE-2011-4081}- jbd/jbd2: validate sb->s_first in journal_get_superblock() (Eryu Guan) {CVE-2011-4132}- KVM: Device assignment permission checks (Joe Jin) {CVE-2011-4347}- KVM: x86: Prevent starting PIT timers in the absence of irqchip support (Jan Kiszka) {CVE-2011-4622}- xfs: validate acl count (Joe Jin) {CVE-2012-0038}- KVM: x86: fix missing checks in syscall emulation (Joe Jin) {CVE-2012-0045}- KVM: x86: extend 'struct x86_emulate_ops' with 'get_cpuid' (Joe Jin) {CVE-2012-0045}- igmp: Avoid zero delay when receiving odd mixture of IGMP queries (Ben Hutchings) {CVE-2012-0207}- ipv4: correct IGMP behavior on v3 query during v2-compatibility mode (David Stevens)- fuse: fix fuse request unique id (Srinivas Eeda) [orabug 13816349][2.6.32-300.10.1.el6uek]- net: remove extra register in ip_gre (Guru Anbalagane) [Orabug: 13633287][2.6.32-300.9.1.el6uek]- [netdrv] fnic: return zero on fnic_reset() success (Joe Jin)- [e1000e] Add entropy generation back for network interrupts (John Sobecki)- [nfs4] LINUX CLIENT TREATS NFS4ERR_GRACE AS A PERMANENT ERROR [orabug 13476821] (John Sobecki)- [nfs] NFS CLIENT CONNECTS TO SERVER THEN DISCONNECTS [orabug 13516759] (John Sobecki)- [sunrpc] Add patch for a mount crash in __rpc_create_common [orabug 13322773] (John Sobecki)[2.6.32-300.8.1.el6uek]- SPEC: fix dependency on firmware/mkinitrd (Guru Anbalagane) [orabug 13637902]- xfs: fix acl count validation in xfs_acl_from_disk() (Dan Carpenter)- [SCSI] scsi_dh: check queuedata pointer before proceeding further (Moger Babu) [orabug 13615419]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-2003");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-2003.html");
script_cve_id("CVE-2011-4081","CVE-2011-4347","CVE-2012-0038","CVE-2012-0045","CVE-2012-0207","CVE-2011-4077","CVE-2011-4132","CVE-2011-4622");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.11.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~300.11.1.el5uek~1.5.7~2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~300.11.1.el5uekdebug~1.5.7~2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~300.11.1.el5uek~1.5.1~4.0.53", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~300.11.1.el5uekdebug~1.5.1~4.0.53", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.11.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~300.11.1.el6uek~1.5.7~0.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~300.11.1.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~300.11.1.el6uek~1.5.1~4.0.47", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~300.11.1.el6uekdebug~1.5.1~4.0.47", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

