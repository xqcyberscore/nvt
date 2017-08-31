# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0481.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123936");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:32 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0481");
script_tag(name: "insight", value: "ELSA-2012-0481 -  kernel security, bug fix, and enhancement update - [2.6.32-220.13.1.el6]- Revert: [fs] NFSv4: include bitmap in nfsv4 get acl data (Sachin Prabhu) [753231 753232] {CVE-2011-4131}[2.6.32-220.12.1.el6]- [net] net_sched: qdisc_alloc_handle() can be too slow (Jiri Pirko) [805458 785891]- [fs] procfs: add hidepid= and gid= mount options (Jerome Marchand) [770651 770652]- [fs] procfs: parse mount options (Jerome Marchand) [770651 770652]- [fs] fuse: add O_DIRECT support (Josef Bacik) [800552 753798]- [kernel] sysctl: restrict write access to dmesg_restrict (Phillip Lougher) [749248 749251]- [block] dm io: fix discard support (Mike Snitzer) [799943 758404]- [net] netlink: wrong size was calculated for vfinfo list blob (Andy Gospodarek) [790338 772136]- [netdrv] mlx4_en: fix endianness with blue frame support (Steve Best) [789911 750166]- [usb] Fix deadlock in hid_reset when Dell iDRAC is reset (Shyam Iyer) [797205 782374]- [virt] vmxnet3: Cap the length of the pskb_may_pull on transmit (bz 790673) (Neil Horman) [801723 790673]- [scsi] megaraid_sas: Fix instance access in megasas_reset_timer (Tomas Henzl) [790341 759318]- [netdrv] macvtap: Fix the minor device number allocation (Steve Best) [796828 786518]- [net] tcp: bind() fix autoselection to share ports (Flavio Leitner) [787764 784671]- [fs] cifs: change oplock break slow work to very slow work (Jeff Layton) [789373 772874]- [net] sunrpc: remove xpt_pool (J. Bruce Fields) [795338 753301]- [net] Potential null skb->dev dereference (Flavio Leitner) [795335 769590]- [net] pkt_sched: Fix sch_sfq vs tcf_bind_filter oops (Jiri Pirko) [786873 667925]- [net] mac80211: cancel auth retries when deauthenticating (John Linville) [797241 754356][2.6.32-220.11.1.el6]- [netdrv] igb: reset PHY after recovering from PHY power down (Frantisek Hrbata) [789371 737714]- [drm] Ivybridge force wake fixes (Dave Airlie) [790007 786272]- [fs] xfs: fix inode lookup race (Dave Chinner) [804961 796277]- [kernel] regset: Return -EFAULT, not -EIO, on host-side memory fault (Jerome Marchand) [799212 799213] {CVE-2012-1097}- [kernel] regset: Prevent null pointer reference on readonly regsets (Jerome Marchand) [799212 799213] {CVE-2012-1097}- [block] Fix io_context leak after failure of clone with CLONE_IO (Vivek Goyal) [796846 791125] {CVE-2012-0879}- [block] Fix io_context leak after clone with CLONE_IO (Vivek Goyal) [796846 791125] {CVE-2012-0879}- [fs] cifs: fix dentry refcount leak when opening a FIFO on lookup (Sachin Prabhu) [798298 781893] {CVE-2012-1090}- [fs] NFSv4: include bitmap in nfsv4 get acl data (Sachin Prabhu) [753231 753232] {CVE-2011-4131}- [mm] fix nrpages assertion (Josef Bacik) [797182 766861]- [mm] Eliminate possible panic in page compaction code (Larry Woodman) [802430 755885]- [mm] Prevent panic on 2-node x3850 X5 w/2 MAX5 memory drawers panics while running certification tests caused by page list corruption (Larry Woodman) [802430 755885]- [sched] Fix cgroup movement of waking process (Larry Woodman) [795326 773517]- [sched] Fix cgroup movement of forking process (Larry Woodman) [795326 773517]- [sched] Fix cgroup movement of newly created process (Larry Woodman) [795326 773517]- [sched] Fix ->min_vruntime calculation in dequeue_entity() (Larry Woodman) [795326 773517]- [sched] cgroup: Fixup broken cgroup movement (Larry Woodman) [795326 773517]- [kernel] Prevent system deadlock when moving tasks between cgroups (Larry Woodman) [789060 773522]- [kernel] sched: fix {s,u}time values decrease (Stanislaw Gruszka) [789061 748559]- [mm] mempolicy.c: refix mbind_range() vma issue (Motohiro Kosaki) [802379 727700]- [mm] mempolicy.c: fix pgoff in mbind vma merge (Motohiro Kosaki) [802379 727700][2.6.32-220.10.1.el6]- [sched] Fix Kernel divide by zero panic in find_busiest_group() (Larry Woodman) [801718 785959][2.6.32-220.9.1.el6]- [x86] Fix c-state transitions when !NOHZ (Prarit Bhargava) [798572 767753]- [x86] tsc: Skip TSC synchronization checks for tsc=reliable (Prarit Bhargava) [798572 767753][2.6.32-220.8.1.el6]- [fs] nfs: don't try to migrate pages with active requests (Jeff Layton) [790905 739811]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0481");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0481.html");
script_cve_id("CVE-2012-0879","CVE-2012-1090","CVE-2012-1097");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.13.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

