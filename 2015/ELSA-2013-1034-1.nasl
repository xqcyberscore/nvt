# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1034-1.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123601");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:06 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1034-1");
script_tag(name: "insight", value: "ELSA-2013-1034-1 -  kernel security and bug fix update - kernel[2.6.18-348.12.1.0.1]- [oprofile] x86, mm: Add __get_user_pages_fast() [orabug 14277030]- [oprofile] export __get_user_pages_fast() function [orabug 14277030]- [oprofile] oprofile, x86: Fix nmi-unsafe callgraph support [orabug 14277030]- [oprofile] oprofile: use KM_NMI slot for kmap_atomic [orabug 14277030]- [oprofile] oprofile: i386 add get_user_pages_fast support [orabug 14277030]- [kernel] Initialize the local uninitialized variable stats. [orabug 14051367]- [fs] JBD:make jbd support 512B blocks correctly for ocfs2. [orabug 13477763]- [x86 ] fix fpu context corrupt when preempt in signal context [orabug 14038272]- [mm] fix hugetlb page leak (Dave McCracken) [orabug 12375075]- fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan)- [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan)- [x86] Fix lvt0 reset when hvm boot up with noapic param- [scsi] remove printks when doing I/O to a dead device (John Sobecki, Chris Mason) [orabug 12342275]- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]- [net] net: Redo the broken redhat netconsole over bonding (Tina Yang) [orabug 12740042]- [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646]- fix filp_close() race (Joe Jin) [orabug 10335998]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] Patch shrink_zone to yield during severe mempressure events, avoiding hangs and evictions (John Sobecki,Chris Mason) [orabug 6086839]- [mm] Enhance shrink_zone patch allow full swap utilization, and also be NUMA-aware (John Sobecki,Chris Mason,Herbert van den Bergh) [orabug 9245919]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- [usb] USB: fix __must_check warnings in drivers/usb/core/ (Junxiao Bi) [orabug 14795203]- [usb] usbcore: fix endpoint device creation (Junxiao Bi) [orabug 14795203]- [usb] usbcore: fix refcount bug in endpoint removal (Junxiao Bi) [orabug 14795203][2.6.18-348.12.1]- Revert: [fs] afs: export a couple of core functions for AFS write support (Lukas Czerner) [960014 692071]- Revert: [fs] ext4: drop ec_type from the ext4_ext_cache structure (Lukas Czerner) [960014 692071]- Revert: [fs] ext4: handle NULL p_ext in ext4_ext_next_allocated_block() (Lukas Czerner) [960014 692071]- Revert: [fs] ext4: make FIEMAP and delayed allocation play well together (Lukas Czerner) [960014 692071]- Revert: [fs] ext4: Fix possibly very long loop in fiemap (Lukas Czerner) [960014 692071]- Revert: [fs] ext4: prevent race while walking extent tree for fiemap (Lukas Czerner) [960014 692071][2.6.18-348.11.1]- Revert: [kernel] kmod: make request_module() killable (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- Revert: [kernel] kmod: avoid deadlock from recursive kmod call (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- Revert: [kernel] wait_for_helper: remove unneeded do_sigaction() (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- Revert: [kernel] Fix ____call_usermodehelper errs being silently ignored (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- Revert: [kernel] wait_for_helper: SIGCHLD from u/s cause use-after-free (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- Revert: [kernel] kmod: avoid deadlock from recursive request_module call (Frantisek Hrbata) [957152 949568]- Revert: [x86-64] non lazy sleazy fpu implementation (Prarit Bhargava) [948187 731531]- Revert: [i386] add sleazy FPU optimization (Prarit Bhargava) [948187 731531]- Revert: [x86] fpu: fix CONFIG_PREEMPT=y corruption of FPU stack (Prarit Bhargava) [948187 731531]- Revert: [ia64] fix KABI breakage on ia64 (Prarit Bhargava) [966878 960783][2.6.18-348.10.1]- [net] Bluetooth: fix possible info leak in bt_sock_recvmsg() (Radomir Vrbovsky) [955600 955601] {CVE-2013-3224}- [net] Bluetooth: HCI & L2CAP information leaks (Jacob Tanenbaum) [922415 922416] {CVE-2012-6544}- [misc] signal: use __ARCH_HAS_SA_RESTORER instead of SA_RESTORER (Nikola Pajkovsky) [920503 920504] {CVE-2013-0914}- [misc] signal: always clear sa_restorer on execve (Nikola Pajkovsky) [920503 920504] {CVE-2013-0914}- [misc] signal: Def __ARCH_HAS_SA_RESTORER for sa_restorer clear (Nikola Pajkovsky) [920503 920504] {CVE-2013-0914}- [net] cxgb4: zero out another firmware request struct (Jay Fenlason) [971872 872531]- [net] cxgb4: clear out most firmware request structures (Jay Fenlason) [971872 872531]- [kernel] Make futex_wait() use an hrtimer for timeout (Prarit Bhargava) [958021 864648][2.6.18-348.9.1]- [net] tg3: buffer overflow in VPD firmware parsing (Jacob Tanenbaum) [949939 949940] {CVE-2013-1929}- [net] atm: update msg_namelen in vcc_recvmsg() (Nikola Pajkovsky) [955222 955223] {CVE-2013-3222}- [fs] ext4: prevent race while walking extent tree for fiemap (Lukas Czerner) [960014 692071]- [fs] ext4: Fix possibly very long loop in fiemap (Lukas Czerner) [960014 692071]- [fs] ext4: make FIEMAP and delayed allocation play well together (Lukas Czerner) [960014 692071]- [fs] ext4: handle NULL p_ext in ext4_ext_next_allocated_block() (Lukas Czerner) [960014 692071]- [fs] ext4: drop ec_type from the ext4_ext_cache structure (Lukas Czerner) [960014 692071]- [fs] afs: export a couple of core functions for AFS write support (Lukas Czerner) [960014 692071]- [net] llc: Fix missing msg_namelen update in llc_ui_recvmsg() (Jesper Brouer) [956096 956097] {CVE-2013-3231}- [net] tipc: fix info leaks via msg_name in recv_msg/recv_stream (Jesper Brouer) [956148 956149] {CVE-2013-3235}- [net] Bluetooth: RFCOMM Fix info leak in ioctl(RFCOMMGETDEVLIST) (Radomir Vrbovsky) [922406 922407] {CVE-2012-6545}- [net] Bluetooth: RFCOMM - Fix info leak via getsockname() (Radomir Vrbovsky) [922406 922407] {CVE-2012-6545}- [kernel] kmod: avoid deadlock from recursive request_module call (Frantisek Hrbata) [957152 949568]- [kernel] wait_for_helper: SIGCHLD from u/s cause use-after-free (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- [kernel] Fix ____call_usermodehelper errs being silently ignored (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- [kernel] wait_for_helper: remove unneeded do_sigaction() (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- [kernel] kmod: avoid deadlock from recursive kmod call (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}- [kernel] kmod: make request_module() killable (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}[2.6.18-348.8.1]- [ia64] fix KABI breakage on ia64 (Prarit Bhargava) [966878 960783][2.6.18-348.7.1]- [pci] intel-iommu: Prev devs with RMRRs from going in SI Domain (Tony Camuso) [957606 839334]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1034-1");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1034-1.html");
script_cve_id("CVE-2013-1929","CVE-2012-6544","CVE-2012-6545","CVE-2013-0914","CVE-2013-3222","CVE-2013-3224","CVE-2013-3231","CVE-2013-3235");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.12.1.0.1.el5~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.12.1.0.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.12.1.0.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~348.12.1.0.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.12.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.12.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.12.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~348.12.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

