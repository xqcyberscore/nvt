# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0004.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122285");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:15:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0004");
script_tag(name: "insight", value: "ELSA-2011-0004 -  kernel security, bug fix, and enhancement update - [2.6.18-194.32.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb (John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin) [orabug 9504524]- [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [mm] Enhance shrink_zone patch allow full swap utilization, and also be NUMA-aware (John Sobecki, Chris Mason, Herbert van den Bergh) [orabug 9245919]- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- make xenkbd.abs_pointer=1 by default (John Haxby) [orabug 67188919]- fix filp_close() race (Joe Jin) [orabug 10335998][2.6.18-194.32.1.el5]- [fs] nfs: set lock_context field in nfs_readpage_sync (Jeff Layton) [664416 663853][2.6.18-194.31.1.el5]- [fs] nfs: set lock_context field in nfs_writepage_sync (Jeff Layton) [663381 660580]- [fs] nfs: remove problematic calls to nfs_clear_request (Jeff Layton) [663353 656492]- [fs] nfs: handle alloc failures in nfs_create_request (Jeff Layton) [663353 656492]- [fs] nfs: clean up nfs_create_request (Jeff Layton) [663353 656492]- [virt] xen: fix netback hotplug regression in xenbus fix (Laszlo Ersek) [636412 635999] {CVE-2010-3699}[2.6.18-194.30.1.el5]- [scsi] lpfc: set heartbeat timer off by default (Rob Evers) [658079 655119]- [misc] posix-cpu-timers: workaround for mt exec problems (Oleg Nesterov) [656265 656266] {CVE-2010-4248}- [fs] setup_arg_pages: diagnose excessive argument size (Oleg Nesterov) [645226 645227] {CVE-2010-3858}- [net] inet_diag: make sure we run audited bytecode (Jiri Pirko) [651266 651267] {CVE-2010-3880}- [net] limit sendto/recvfrom/iovec total length to INT_MAX (Jiri Pirko) [645871 645872] {CVE-2010-3859}- [bluetooth] hci_ldisc: fix missing NULL check (Jarod Wilson) [655664 655666] {CVE-2010-4242}- [virt] xen: add bounds req-process loop in blkback/blktap (Laszlo Ersek) [656208 654546] {CVE-2010-4247}- [virt] xen: don't leak dev refs on bad xenbus transitions (Laszlo Ersek) [636412 635999] {CVE-2010-3699}- [scsi] lpfc: fix crashes on NULL pnode dereference (Rob Evers) [658864 649489]- [scsi] qla2xxx: check null fcport in _queuecommands (Chad Dupuis) [657029 644863]- [fs] gfs2: fix race in unlinked inode deallocation (Robert S Peterson) [651811 643165]- [scsi] lpfc: fix a BUG_ON in lpfc_abort_handler (Rob Evers) [658378 639028]- [scsi] re-enable transistions from OFFLINE to RUNNING (Mike Christie) [658934 641193]- [scsi] scsi_dh_alua: handle transitioning state correctly (Mike Snitzer) [657028 619361]- [misc] add round_jiffies_up and related routines (Michal Schmidt) [658520 556476]- [fs] fix dcache accounting bug (Josef Bacik) [658857 596548]- [usb] uhci: fix oops in uhci_scan_schedule (Pete Zaitcev) [657319 516851]- [scsi] lpfc: fix panic in lpfc_scsi_cmd_iocb_cmpl (Rob Evers) [658379 603806][2.6.18-194.29.1.el5]- [net] rds: fix rds_iovec page count overflow (Jiri Pirko) [647421 647422] {CVE-2010-3865}- [net] fix deadlock in sock_queue_rcv_skb (Danny Feng) [652536 652537] {CVE-2010-4161}- [net] packet: fix information leak to userland (Jiri Pirko) [649897 649898] {CVE-2010-3876}- [ipc] sys_semctl: fix kernel stack leakage (Danny Feng) [648721 648722] {CVE-2010-4083}- [misc] kernel: remove yield from stop_machine paths (Oleg Nesterov) [651818 634454]- [fs] dlm: reduce cond_resched during send (David Teigland) [653335 604139]- [fs] dlm: use TCP_NODELAY (David Teigland) [653335 604139]- [net] sctp: do not reset packet during sctp_packet_config (Jiri Pirko) [637866 637867] {CVE-2010-3432}- [net] bonding: no lock on copy/clear VLAN list on slave (Andy Gospodarek) [652561 627974]- [scsi] gdth: prevent integer overflow in ioc_general (Frantisek Hrbata) [651175 651176] {CVE-2010-4157}- [kernel] add stop_machine barrier to fix lock contention (Prarit Bhargava) [651818 634454][2.6.18-194.28.1.el5]- [net] bnx2: Increase max rx ring size from 1K to 2K (Andy Gospodarek) [649255 640026]- [net] bnx2: fixup broken NAPI accounting (Andy Gospodarek) [649255 640026]- [pci] include DL580 G7 in bfsort whitelist (Tony Camuso) [646765 644879]- [sound] core: prevent heap corruption in snd_ctl_new (Jerome Marchand) [638483 638484] {CVE-2010-3442}- [net] ixgbe: add option to control interrupt mode (Andy Gospodarek) [643339 571495]- [fs] execve: fix interactivity and response to SIGKILL (Dave Anderson) [643344 629176]- [usb] fix test of wrong variable in create_by_name (Don Howard) [643347 594635]- [fs] gfs2: fix stuck in inode wait, no glocks stuck (Robert S Peterson) [651805 595397]- [net] gro: fix bogus gso_size on the first fraglist entry (Herbert Xu) [648938 588015]- [virt] xen: fix Connected state after netback dev closed (Paolo Bonzini) [643345 591548]- [net] tun: orphan an skb on tx (Michael S. Tsirkin) [643348 584412][2.6.18-194.27.1.el5]- [net] netxen: fix set mac addr (Andy Gospodarek) [647681 562937]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0004");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0004.html");
script_cve_id("CVE-2010-3432","CVE-2010-3442","CVE-2010-3699","CVE-2010-3858","CVE-2010-3859","CVE-2010-3865","CVE-2010-3876","CVE-2010-3880","CVE-2010-4083","CVE-2010-4157","CVE-2010-4161","CVE-2010-4242","CVE-2010-4247","CVE-2010-4248");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.32.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.32.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.32.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.32.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.32.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.32.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.32.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.32.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.32.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

