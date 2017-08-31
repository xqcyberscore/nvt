# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0833.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122155");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0833");
script_tag(name: "insight", value: "ELSA-2011-0833 -  kernel security and bug fix update - [2.6.18-238.12.1.0.1.el5]- [scsi] fix scsi hotplug and rescan race [orabug 10260172]- fix filp_close() race (Joe Jin) [orabug 10335998]- fix missing aio_complete() in end_io (Joel Becker) [orabug 10365195]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [nfs] too many getattr and access calls after direct I/O [orabug 9348191]- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- [aio] patch removes limit on number of retries (Srinivas Eeda) [orabug 10044782]- [loop] Do not call loop_unplug for not configured loop device (orabug 10314497)[2.6.18-238.12.1.el5]- [x86_64] Ignore spurious IPIs left over from crash kernel (Myron Stowe) [699610 692921]- [i386] Ignore spurious IPIs left over from crash kernel (Myron Stowe) [699610 692921]- [xen] fix MAX_EVTCHNS definition (Laszlo Ersek) [701242 701240]- [net] ixgbe: fix for link failure on SFP+ DA cables (Don Howard) [696181 653236]- [net] netxen: limit skb frags for non tso packet (Phillip Lougher) [699609 672368]- [block] cciss: fix lost command problem (Phillip Lougher) [696503 696153]- [fs] gfs2: fix filesystem hang caused by incorrect lock order (Robert S Peterson) [688855 656032]- [fs] gfs2: restructure reclaim of unlinked dinodes (Phillip Lougher) [688855 656032]- [fs] gfs2: unlock on gfs2_trans_begin error (Robert S Peterson) [688855 656032]- [scsi] mpt2sas: prevent heap overflows and unchecked access (Tomas Henzl) [694526 694527] {CVE-2011-1495 CVE-2011-1494}- [net] bridge/netfilter: fix ebtables information leak (Don Howard) [681325 681326] {CVE-2011-1080}- [net] bluetooth: fix sco information leak to userspace (Don Howard) [681310 681311] {CVE-2011-1078}- [fs] fix corrupted GUID partition table kernel oops (Jerome Marchand) [695979 695980] {CVE-2011-1577}- [xen] x86/domain: fix error checks in arch_set_info_guest (Laszlo Ersek) [688581 688582] {CVE-2011-1166}- [net] bridge: fix initial packet flood if !STP (Jiri Pirko) [701222 695369]- [fs] nfsd: fix auth_domain reference leak on nlm operations (J. Bruce Fields) [697448 589512]- [scsi] qla2xxx: no reset/fw-dump on CT/ELS pt req timeout (Chad Dupuis) [689700 660386]- [mm] set barrier and send tlb flush to all affected cpus (Prarit Bhargava) [696908 675793][2.6.18-238.11.1.el5]- [s390] dasd: fix race between open and offline (Hendrik Brueckner) [699808 695357][2.6.18-238.10.1.el5]- [fs] gfs2: creating large files suddenly slow to a crawl (Robert S Peterson) [690239 683155]- [virt] hypervisor: Overflow fix for clocks > 4GHz (Zachary Amsden) [690134 673242]- [usb] fix usbfs isochronous data transfer regression (Don Zickus) [696136 688926]- [fs] partitions: Fix corrupted OSF partition table parsing (Danny Feng) [688022 688023] {CVE-2011-1163}- [misc] pm: add comment explaining is_registered kabi work-around (Don Zickus) [689699 637930]- [media] sn9c102: fix world-wirtable sysfs files (Don Howard) [679304 679305]- [scsi] scsi_dh_rdac: Add two new IBM devices to rdac_dev_list (Rob Evers) [692370 691460]- [fs] block: fix submit_bh discarding barrier flag on sync write (Lukas Czerner) [690795 667673]- [net] netfilter/ipt_CLUSTERIP: fix buffer overflow (Jiri Pirko) [689339 689340]- [net] netfilter: ip6_tables: fix infoleak to userspace (Jiri Pirko) [689348 689349] {CVE-2011-1172}- [net] netfilter/ip_tables: fix infoleak to userspace (Jiri Pirko) [689331 689332] {CVE-2011-1171}- [net] netfilter/arp_tables: fix infoleak to userspace (Jiri Pirko) [689322 689323] {CVE-2011-1170}- [base] Fix potential deadlock in driver core (Don Zickus) [689699 637930]- [net] forcedeth/r8169: call netif_carrier_off at end of probe (Ivan Vecera) [689808 689805 664705 664707]- [net] ixgbe: fix for 82599 erratum on Header Splitting (Andy Gospodarek) [693751 680531]- [net] ixgbe: limit VF access to network traffic (Andy Gospodarek) [693751 680531]- [fs] lockd: make lockd_down wait for lockd to come down (Jeff Layton) [688156 653286]- [fs] proc: protect mm start_/end_code in /proc/pid/stat (Eugene Teo) [684570 684571] {CVE-2011-0726}- [net] dccp: fix oops in dccp_rcv_state_process (Eugene Teo) [682955 682956] {CVE-2011-1093}- [net] bluetooth: fix bnep buffer overflow (Don Howard) [681318 681319] {CVE-2011-1079}- [fs] nfs: break nfsd v4 lease on unlink, link, and rename (J. Bruce Fields) [693755 610093]- [fs] nfs: break lease on nfsd v4 setattr (J. Bruce Fields) [693755 610093]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0833");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0833.html");
script_cve_id("CVE-2011-0726","CVE-2011-1078","CVE-2011-1079","CVE-2011-1080","CVE-2011-1093","CVE-2011-1163","CVE-2011-1166","CVE-2011-1170","CVE-2011-1171","CVE-2011-1172","CVE-2011-1494","CVE-2011-1495","CVE-2011-1577","CVE-2011-1763");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.12.1.0.1.el5~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.12.1.0.1.el5PAE~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.12.1.0.1.el5debug~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.12.1.0.1.el5xen~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.12.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.12.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.12.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.12.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

