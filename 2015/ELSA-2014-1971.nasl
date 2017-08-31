# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1971.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123230");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:01 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1971");
script_tag(name: "insight", value: "ELSA-2014-1971 -  kernel security and bug fix update - [3.10.0-123.13.1]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-123.13.1]- [powerpc] mm: Make sure a local_irq_disable prevent a parallel THP split (Don Zickus) [1151057 1083296]- [powerpc] Implement __get_user_pages_fast() (Don Zickus) [1151057 1083296]- [scsi] vmw_pvscsi: Some improvements in pvscsi driver (Ewan Milne) [1144016 1075090]- [scsi] vmw_pvscsi: Add support for I/O requests coalescing (Ewan Milne) [1144016 1075090]- [scsi] vmw_pvscsi: Fix pvscsi_abort() function (Ewan Milne) [1144016 1075090][3.10.0-123.12.1]- [alsa] control: Make sure that id->index does not overflow (Jaroslav Kysela) [1117313 1117314] {CVE-2014-4656}- [alsa] control: Handle numid overflow (Jaroslav Kysela) [1117313 1117314] {CVE-2014-4656}- [alsa] control: Protect user controls against concurrent access (Jaroslav Kysela) [1117338 1117339] {CVE-2014-4652}- [alsa] control: Fix replacing user controls (Jaroslav Kysela) [1117323 1117324] {CVE-2014-4654 CVE-2014-4655}- [net] sctp: fix remote memory pressure from excessive queueing (Daniel Borkmann) [1155750 1152755] {CVE-2014-3688}- [net] sctp: fix panic on duplicate ASCONF chunks (Daniel Borkmann) [1155737 1152755] {CVE-2014-3687}- [net] sctp: fix skb_over_panic when receiving malformed ASCONF chunks (Daniel Borkmann) [1147856 1152755] {CVE-2014-3673}- [net] sctp: handle association restarts when the socket is closed (Daniel Borkmann) [1147856 1152755] [1155737 1152755] [1155750 1152755]- [pci] Add ACS quirk for Intel 10G NICs (Alex Williamson) [1156447 1141399]- [pci] Add ACS quirk for Solarflare SFC9120 & SFC9140 (Alex Williamson) [1158316 1131552]- [lib] assoc_array: Fix termination condition in assoc array garbage collection (David Howells) [1155136 1139431] {CVE-2014-3631}- [block] cfq-iosched: Add comments on update timing of weight (Vivek Goyal) [1152874 1116126]- [block] cfq-iosched: Fix wrong children_weight calculation (Vivek Goyal) [1152874 1116126]- [powerpc] mm: Check paca psize is up to date for huge mappings (Gustavo Duarte) [1151927 1107337]- [x86] perf/intel: ignore CondChgd bit to avoid false NMI handling (Don Zickus) [1146819 1110264]- [x86] smpboot: initialize secondary CPU only if master CPU will wait for it (Phillip Lougher) [1144295 968147]- [x86] smpboot: Log error on secondary CPU wakeup failure at ERR level (Igor Mammedov) [1144295 968147]- [x86] smpboot: Fix list/memory corruption on CPU hotplug (Igor Mammedov) [1144295 968147]- [acpi] processor: do not mark present at boot but not onlined CPU as onlined (Igor Mammedov) [1144295 968147]- [fs] udf: Avoid infinite loop when processing indirect ICBs (Jacob Tanenbaum) [1142321 1142322] {CVE-2014-6410}- [hid] picolcd: fix memory corruption via OOB write (Jacob Tanenbaum) [1141408 1141409] {CVE-2014-3186}- [usb] serial/whiteheat: fix memory corruption flaw (Jacob Tanenbaum) [1141403 1141404] {CVE-2014-3185}- [hid] fix off by one error in various _report_fixup routines (Jacob Tanenbaum) [1141393 1141394] {CVE-2014-3184}- [hid] logitech-dj: fix OOB array access (Jacob Tanenbaum) [1141211 1141212] {CVE-2014-3182}- [hid] fix OOB write in magicmouse driver (Jacob Tanenbaum) [1141176 1141177] {CVE-2014-3181}- [acpi] Fix bug when ACPI reset register is implemented in system memory (Nigel Croxon) [1136525 1109971]- [fs] vfs: fix ref count leak in path_mountpoint() (Ian Kent) [1122481 1122376] {CVE-2014-5045}- [kernel] ptrace: get_dumpable() incorrect tests (Jacob Tanenbaum) [1111605 1111606] {CVE-2013-2929}- [media] media-device: fix an information leakage (Jacob Tanenbaum) [1109776 1109777] {CVE-2014-1739}- [target] rd: Refactor rd_build_device_space + rd_release_device_space (Denys Vlasenko) [1108754 1108755] {CVE-2014-4027}- [block] blkcg: fix use-after-free in __blkg_release_rcu() by making blkcg_gq refcnt an atomic_t (Vivek Goyal) [1158313 1118436]- [virt] kvm: fix PIT timer race condition (Petr Matousek) [1144879 1144880] {CVE-2014-3611}- [virt] kvm/vmx: handle invept and invvpid vm exits gracefully (Petr Matousek) [1145449 1116936] [1144828 1144829] {CVE-2014-3645 CVE-2014-3646}[3.10.0-123.11.1]- [net] fix UDP tunnel GSO of frag_list GRO packets (Phillip Lougher) [1149661 1119392][3.10.0-123.10.1]- [pci] hotplug: Prevent NULL dereference during pciehp probe (Myron Stowe) [1142393 1133107]- [kernel] workqueue: apply __WQ_ORDERED to create_singlethread_workqueue() (Tomas Henzl) [1151314 1131563]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1971");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1971.html");
script_cve_id("CVE-2013-2929","CVE-2014-4654","CVE-2014-4655","CVE-2014-5045","CVE-2014-3185","CVE-2014-3181","CVE-2014-3687","CVE-2014-3673","CVE-2014-3184","CVE-2014-1739","CVE-2014-3182","CVE-2014-3186","CVE-2014-3631","CVE-2014-3688","CVE-2014-4027","CVE-2014-4652","CVE-2014-4656","CVE-2014-6410");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.13.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

