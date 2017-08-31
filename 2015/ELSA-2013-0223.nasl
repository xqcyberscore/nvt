# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0223.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123733");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:50 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0223");
script_tag(name: "insight", value: "ELSA-2013-0223 -  kernel security and bug fix update - [2.6.32-279.22.1]- [virt] kvm: invalid opcode oops on SET_SREGS with OSXSAVE bit set (Petr Matousek) [862903 862904] {CVE-2012-4461}- [fs] fuse: optimize __fuse_direct_io() (Brian Foster) [865305 858850]- [fs] fuse: optimize fuse_get_user_pages() (Brian Foster) [865305 858850]- [fs] fuse: use get_user_pages_fast() (Brian Foster) [865305 858850]- [fs] fuse: pass iov[] to fuse_get_user_pages() (Brian Foster) [865305 858850]- [fs] mm: minor cleanup of iov_iter_single_seg_count() (Brian Foster) [865305 858850]- [fs] fuse: use req->page_descs[] for argpages cases (Brian Foster) [865305 858850]to fuse_req (Brian Foster) [865305 858850]- [fs] fuse: rework fuse_do_ioctl() (Brian Foster) [865305 858850]- [fs] fuse: rework fuse_perform_write() (Brian Foster) [865305 858850]- [fs] fuse: rework fuse_readpages() (Brian Foster) [865305 858850]- [fs] fuse: categorize fuse_get_req() (Brian Foster) [865305 858850]- [fs] fuse: general infrastructure for pages[] of variable size (Brian Foster) [865305 858850]- [fs] exec: do not leave bprm->interp on stack (Josh Poimboeuf) [880145 880146] {CVE-2012-4530}- [fs] exec: use -ELOOP for max recursion depth (Josh Poimboeuf) [880145 880146] {CVE-2012-4530}- [scsi] have scsi_internal_device_unblock take new state (Frantisek Hrbata) [878774 854140]- [scsi] add new SDEV_TRANSPORT_OFFLINE state (Chris Leech) [878774 854140]- [kernel] cpu: fix cpu_chain section mismatch (Frederic Weisbecker) [876090 852148]- [kernel] sched: Don't modify cpusets during suspend/resume (Frederic Weisbecker) [876090 852148]- [kernel] sched, cpuset: Drop __cpuexit from cpu hotplug callbacks (Frederic Weisbecker) [876090 852148]- [kernel] sched: adjust when cpu_active and cpuset configurations are updated during cpu on/offlining (Frantisek Hrbata) [876090 852148]- [kernel] cpu: return better errno on cpu hotplug failure (Frederic Weisbecker) [876090 852148]- [kernel] cpu: introduce cpu_notify(), __cpu_notify(), cpu_notify_nofail() (Frederic Weisbecker) [876090 852148]- [fs] nfs: Properly handle the case where the delegation is revoked (Steve Dickson) [846840 842435]- [fs] nfs: Move cl_delegations to the nfs_server struct (Steve Dickson) [846840 842435]- [fs] nfs: Introduce nfs_detach_delegations() (Steve Dickson) [846840 842435]- [fs] nfs: Fix a number of RCU issues in the NFSv4 delegation code (Steve Dickson) [846840 842435][2.6.32-279.21.1]- [scsi] mpt2sas: fix for driver fails EEH recovery from injected pci bus error (Tomas Henzl) [888818 829149]- [net] bonding: Bonding driver does not consider the gso_max_size setting of slave devices (Ivan Vecera) [886618 883643]- [netdrv] tg3: Do not set TSS for 5719 and 5720 (John Feeney) [888215 823371]- [kernel] kmod: make __request_module() killable (Oleg Nesterov) [858755 819529] {CVE-2012-4398}- [kernel] kmod: introduce call_modprobe() helper (Oleg Nesterov) [858755 819529] {CVE-2012-4398}- [kernel] usermodehelper: implement UMH_KILLABLE (Oleg Nesterov) [858755 819529] {CVE-2012-4398}- [kernel] usermodehelper: introduce umh_complete(sub_info) (Oleg Nesterov) [858755 819529] {CVE-2012-4398}- [kernel] call_usermodehelper: simplify/fix UMH_NO_WAIT case (Oleg Nesterov) [858755 819529] {CVE-2012-4398}- [kernel] wait_for_helper: SIGCHLD from user-space can lead to use-after-free (Oleg Nesterov) [858755 819529] {CVE-2012-4398}- [net] sunrpc: Ensure that rpc_release_resources_task() can be called twice (Jeff Layton) [880928 878204]- [scsi] qla2xxx: Don't toggle RISC interrupt bits after IRQ lines are attached. (Chad Dupuis) [886760 826565]- [kernel] rcu: Remove function versions of __kfree_rcu and offset (Doug Ledford) [880085 873949]- [kernel] rcu: define __rcu address space modifier for sparse (Doug Ledford) [880085 873949]- [kernel] rcu: Add rcu_access_pointer and rcu_dereference_protected (Doug Ledford) [880085 873949]- [kernel] rcu: Add lockdep checking to rhel (Doug Ledford) [880085 873949]- [kernel] rcu: Make __kfree_rcu() less dependent on compiler choices (Doug Ledford) [880085 873949]- [kernel] rcu: introduce kfree_rcu() (Doug Ledford) [880085 873949]- [net] rcu: add __rcu API for later sparse checking (Doug Ledford) [880085 873949]- [infiniband] ipoib: Fix AB-BA deadlock when deleting neighbours (Doug Ledford) [880085 873949]- [infiniband] ipoib: Fix memory leak in the neigh table deletion flow (Doug Ledford) [880085 873949]- [infiniband] ipoib: Fix RCU pointer dereference of wrong object (Doug Ledford) [880085 873949]- [misc] Make rcu_dereference_bh work (Doug Ledford) [880085 873949]- [infiniband] ipoib: Use a private hash table for path lookup in xmit path (Doug Ledford) [880085 873949][2.6.32-279.20.1]- [scsi] hpsa: Use LUN reset instead of target reset (Tomas Henzl) [884422 875091]- [char] tty: Fix possible race in n_tty_read() (Stanislaw Gruszka) [891580 765665]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0223");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0223.html");
script_cve_id("CVE-2012-4398","CVE-2012-4461","CVE-2012-4530");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.22.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

