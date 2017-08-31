# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1426.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123787");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:33 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1426");
script_tag(name: "insight", value: "ELSA-2012-1426 -  kernel security and bug fix update - [2.6.32-279.14.1.el6]- [usb] usbhid: Fix use-after-free in USBHID (James Paradis) [864827 857518]- [usb] Add kernel parameter to force io_watchdog for Intel EHCI HCD (James Paradis) [865713 846024]- [block] Fix hanging kernel threads in blk_execute_rq() (James Paradis) [865308 855984]- [mm] hugetlb: do not use vma_hugecache_offset() for vma_prio_tree_foreach (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}- [mm] hugepages: fix use after free bug in 'quota' handling (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}- [mm] hugetlb: fix pgoff computation when unmapping page from vma (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}- [mm] hugetlb: fix ENOSPC returned by handle_mm_fault() (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}- [fs] gfs2: Write out dirty inode metadata in delayed deletes (Frantisek Hrbata) [859326 748827]- [usb] core: Fix device removal race condition (James Paradis) [864821 849188]- [mm] x86_32: fix SHLIB_BASE address typo (Aristeu S. Rozanski F) [804955 804956] {CVE-2012-1568}- [hid] hidraw: fix window in hidraw_release (Don Zickus) [841824 839973]- [hid] hidraw: protect hidraw_disconnect() better (Don Zickus) [841824 839973]- [hid] hidraw: remove excessive _EMERG messages from hidraw (Don Zickus) [841824 839973]- [hid] hidraw: fix hidraw_disconnect() (Don Zickus) [841824 839973]- [hid] fix a NULL pointer dereference in hidraw_write (Don Zickus) [841824 839973]- [hid] fix a NULL pointer dereference in hidraw_ioctl (Don Zickus) [841824 839973]- [hid] remove BKL from hidraw (Don Zickus) [841824 839973]- [mm] x86_32: randomize SHLIB_BASE (Aristeu Rozanski) [804955 804956] {CVE-2012-1568}- [block] fix up use after free in __blkdev_get (Jeff Moyer) [853943 847838]- [scsi] remove no longer valid BUG_ON in scsi_lld_busy (Jeff Garzik) [860640 842881]- [scsi] fix NULL request_queue in scsi_requeue_run_queue() (Jeff Garzik) [860640 842881]- [net] svcrpc: fix BUG() in svc_tcp_clear_pages (J. Bruce Fields) [856106 769045]- [scsi] lpfc: Fixed SCSI device reset escalation (Rob Evers) [861390 827566]- [scsi] lpfc: Fix abort status (Rob Evers) [861390 827566]- [kernel] cgroup: add cgroup_root_mutex (Frederic Weisbecker) [858954 844531]- [mm] Hold a file reference in madvise_remove (Jerome Marchand) [849738 849739] {CVE-2012-3511}- [base] driver-core: fix device_register race (Rob Evers) [860784 833098]- [netdrv] e1000e: drop check of RXCW.CW to eliminate link going up and down (Dean Nelson) [857055 847310]- [scsi] be2iscsi: Format the MAC_ADDR with sysfs (Rob Evers) [863147 827594]- [usb] usbdevfs: Add a USBDEVFS_GET_CAPABILITIES ioctl (Don Zickus) [841667 828271]- [fs] udf: fix retun value on error path in udf_load_logicalvol (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}- [fs] udf: Improve table length check to avoid possible overflow (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}- [fs] udf: Fortify loading of sparing table (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}- [fs] udf: Avoid run away loop when partition table length is corrupted (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}- [fs] udf: Use 'ret' instead of abusing 'i' in udf_load_logicalvol() (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}- [netdrv] bnx2x: Add remote-fault link detection (Michal Schmidt) [852450 814877]- [net] sunrpc: svc_xprt sends on closed socket should stop immediately (J. Bruce Fields) [853257 849702]- [mm] Never OOM kill tasks outside of memory cgroup when memory.limit_in_bytes is exceeded by a Transparent Huge Page (Larry Woodman) [860942 811255]- [powerpc] pseries: Support lower minimum entitlement for virtual processors (Steve Best) [860165 822651]- [usbhid] hiddev: Consolidate device existence checks in hiddev_ioctl (Don Zickus) [841824 839973]- [usbhid] hiddev: Fix race between disconnect and hiddev_ioctl (Don Zickus) [841824 839973]- [usbhid] hiddev: protect against disconnect/NULL-dereference race (Don Zickus) [841824 839973]- [crypto] algapi: Move larval completion into algboss (Herbert Xu) [854476 832135]- [fs] xfs: disable xfsaild idle mode (Brian Foster) [860787 813137]- [fs] xfs: fix the logspace waiting algorithm (Brian Foster) [860787 813137]- [fs] xfs: add AIL pushing tracepoints (Brian Foster) [860787 813137]- [fs] xfs: force the log if we encounter pinned buffers in .iop_pushbuf (Brian Foster) [860787 813137]- [fs] xfs: do not update xa_last_pushed_lsn for locked items (Brian Foster) [860787 813137][2.6.32-279.13.1.el6]- [net] sctp: Implement quick failover draft from tsvwg (Neil Horman) [861953 830716]- [net] sctp: be more restrictive in transport selection on bundled sacks (Neil Horman) [861953 830716][2.6.32-279.12.1.el6]- [netdrv] mlx4: check promisc on proper port (Doug Ledford) [858955 854052]- [netdrv] mlx4: attach multicast with correct flag (Doug Ledford) [858956 854376]- [netdrv] mlx4: remove redundant adding of steering type to gid (Doug Ledford) [859436 854053]- [netdrv] Revert: Fix a merge issue (Doug Ledford) [859436 854053]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1426");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1426.html");
script_cve_id("CVE-2012-1568","CVE-2012-2133","CVE-2012-3400","CVE-2012-3511");
script_tag(name:"cvss_base", value:"7.6");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

