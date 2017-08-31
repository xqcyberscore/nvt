# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0630.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123664");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0630");
script_tag(name: "insight", value: "ELSA-2013-0630 -  kernel security and bug fix update - [2.6.32-358.2.1]- [kernel] utrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg Nesterov) [912073 912074] {CVE-2013-0871}[2.6.32-358.1.1]- [netdrv] mlx4: Set number of msix vectors under SRIOV mode to firmware defaults (Michal Schmidt) [911663 904726]- [netdrv] mlx4: Fix bridged vSwitch configuration for non SRIOV mode (Michal Schmidt) [910998 903644]- [net] rtnetlink: Fix IFLA_EXT_MASK definition (regression) (Thomas Graf) [909815 903220]- [x86] msr: Add capabilities check (Nikola Pajkovsky) [908698 908699] {CVE-2013-0268}- [x86] msr: Remove incorrect, duplicated code in the MSR driver (Nikola Pajkovsky) [908698 908699] {CVE-2013-0268}- [virt] xen: dont assume ds is usable in xen_iret for 32-bit PVOPS (Andrew Jones) [906310 906311] {CVE-2013-0228}- [kernel] cputime: Avoid multiplication overflow on utime scaling (Stanislaw Gruszka) [908794 862758]- [net] sunrpc: When changing the queue priority, ensure that we change the owner (Steve Dickson) [910370 902965]- [net] sunrpc: Ensure we release the socket write lock if the rpc_task exits early (Steve Dickson) [910370 902965]- [fs] nfs: Ensure that we free the rpc_task after read and write cleanups are done (Steve Dickson) [910370 902965]- [net] sunrpc: Ensure that we free the rpc_task after cleanups are done (Steve Dickson) [910370 902965]- [net] sunrpc: Dont allow low priority tasks to pre-empt higher priority ones (Steve Dickson) [910370 902965]- [fs] nfs: Add sequence_priviliged_ops for nfs4_proc_sequence() (Steve Dickson) [910370 902965]- [fs] nfs: The NFSv4.0 client must send RENEW calls if it holds a delegation (Steve Dickson) [910370 902965]- [fs] nfs: nfs4_proc_renew should be declared static (Steve Dickson) [910370 902965]- [fs] nfs: nfs4_locku_done must release the sequence id (Steve Dickson) [910370 902965]- [fs] nfs: We must release the sequence id when we fail to get a session slot (Steve Dickson) [910370 902965]- [fs] nfs: Add debugging messages to NFSv4s CLOSE procedure (Steve Dickson) [910370 902965]- [net] sunrpc: Clear the connect flag when socket state is TCP_CLOSE_WAIT (Steve Dickson) [910370 902965]- [fs] nfs: cleanup DS stateid error handling (Steve Dickson) [910370 902965]- [fs] nfs: handle DS stateid errors (Steve Dickson) [910370 902965]- [fs] nfs: Fix potential races in xprt_lock_write_next() (Steve Dickson) [910370 902965]- [fs] nfs: Ensure correct locking when accessing the 'lock_states' list (Steve Dickson) [910370 902965]- [fs] nfs: Fix the handling of NFS4ERR_SEQ_MISORDERED errors (Steve Dickson) [910370 902965]- [netdrv] be2net: fix unconditionally returning IRQ_HANDLED in INTx (Ivan Vecera) [910373 909464]- [netdrv] be2net: fix INTx ISR for interrupt behaviour on BE2 (Ivan Vecera) [910373 909464]- [netdrv] be2net: fix a possible events_get() race on BE2 (Ivan Vecera) [910373 909464]- [fs] gfs2: Get a block reservation before resizing a file (Robert S Peterson) [908398 875753]- [net] ipv6: do not create neighbor entries for local delivery (Jiri Pirko) [909159 896020]- [net] bonding: check for assigned mac before adopting the slaves mac address (Veaceslav Falico) [908737 905126]- [fs] nfs: nfs4_xdr_enc_layout{commit, return} must return status (Steve Dickson) [908733 907227]- [fs] set s_type before destroy_super in sget() (Eric Sandeen) [909813 904982]- [scsi] ses: Avoid kernel panic when lun 0 is not mapped (Ewan Milne) [908739 886867]- [block] avoid divide-by-zero with zero discard granularity (Mike Snitzer) [911000 901705]- [block] discard granularity might not be power of 2 (Mike Snitzer) [911000 901705]- [netdrv] tg3: Fix crc errors on jumbo frame receive (Ivan Vecera) [909816 895336]- [netdrv] igb: set E1000_IMS_TS interrupt bit in igb_irq_enable (Stefan Assmann) [909818 871795]- [pci] intel-iommu: Prevent devices with RMRRs from being placed into SI Domain (Tony Camuso) [908744 678451]- [scsi] sd: Reshuffle init_sd to avoid crash (Ewan Milne) [911655 888417]- [mm] add numa node symlink for cpu devices in sysfs (Neil Horman) [909814 878708]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0630");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0630.html");
script_cve_id("CVE-2013-0228","CVE-2013-0268");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

