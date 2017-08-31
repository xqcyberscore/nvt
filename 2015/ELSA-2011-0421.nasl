# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0421.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122198");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:41 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0421");
script_tag(name: "insight", value: "ELSA-2011-0421 -  kernel security and bug fix update - [2.6.32-71.24.1.el6]- [fs] Revert '[fs] inotify: stop kernel memory leak on file creation failure' (Eric Paris) [656831 656832] {CVE-2010-4250}[2.6.32-71.23.1.el6]- [x86] Revert '[x86] mtrr: Assume SYS_CFG[Tom2ForceMemTypeWB] exists on all future AMD CPUs' (Frank Arnold) [683813 652208][2.6.32-71.22.1.el6]- rebuild[2.6.32-71.21.1.el6]- [netdrv] ixgbe: limit VF access to network traffic (Frantisek Hrbata) [684129 678717]- [netdrv] ixgbe: work around for DDP last buffer size (Frantisek Hrbata) [684129 678717]- [net] gro: reset dev and skb_iff on skb reuse (Andy Gospodarek) [688311 681970]- [x86] mtrr: Assume SYS_CFG[Tom2ForceMemTypeWB] exists on all future AMD CPUs (Frank Arnold) [683813 652208]- [virt] virtio_net: Add schedule check to napi_enable call (Michael S. Tsirkin) [684268 676579]- [s390x] mm: add devmem_is_allowed() for STRICT_DEVMEM checking (Hendrik Brueckner) [684267 647365]- [powerpc] Don't use kernel stack with translation off (Steve Best) [684266 628951]- [powerpc] Initialise paca->kstack before early_setup_secondary (Steve Best) [684266 628951][2.6.32-71.20.1.el6]- [dvb] kernel: av7110 negative array offset (Mauro Carvalho Chehab) [672403 672404] {CVE-2011-0521}- [fs] sunrpc: Correct a misapplied patch (J. Bruce Fields) [678094 678146] {CVE-2011-0714}- [netdrv] orinoco: fix TKIP countermeasure behaviour (Stanislaw Gruszka) [667908 667909] {CVE-2010-4648}- [kernel] /proc/vmcore: speed up access to vmcore file (Neil Horman) [683442 672937]- [netdrv] cnic: Fix big endian bug (Steve Best) [678484 676640]- [scsi] fcoe: drop FCoE LOGO in FIP mode (Mike Christie) [683814 668114]- [s390x] remove task_show_regs (Danny Feng) [677854 677855] {CVE-2011-0710}- [ib] cm: Bump reference count on cm_id before invoking callback (Doug Ledford) [676190 676191] {CVE-2011-0695}- [rdma] cm: Fix crash in request handlers (Doug Ledford) [676190 676191] {CVE-2011-0695}- [net] bridge: Fix mglist corruption that leads to memory corruption (Herbert Xu) [678172 659421] {CVE-2011-0716}- [netdrv] r8169: use RxFIFO overflow workaround and prevent RxFIFO induced infinite loops (Ivan Vecera) [680080 630810]- [s390x] kernel: nohz vs cpu hotplug system hang (Hendrik Brueckner) [683815 668470]- [netdrv] cxgb3/cxgb3_main.c: prevent reading uninitialized stack memory (Doug Ledford) [633156 633157] {CVE-2010-3296}- [configs] redhat: added CONFIG_SECURITY_DMESG_RESTRICT option (Frantisek Hrbata) [683822 653245]- [kernel] restrict unprivileged access to kernel syslog (Frantisek Hrbata) [683822 653245]- [fs] cifs: allow matching of tcp sessions in CifsNew state (Jeff Layton) [683812 629085]- [fs] cifs: fix potential double put of TCP session reference (Jeff Layton) [683812 629085]- [fs] cifs: prevent possible memory corruption in cifs_demultiplex_thread (Jeff Layton) [683812 629085]- [fs] cifs: eliminate some more premature cifsd exits (Jeff Layton) [683812 629085]- [fs] cifs: prevent cifsd from exiting prematurely (Jeff Layton) [683812 629085]- [fs] CIFS: Make cifs_convert_address() take a const src pointer and a length (Jeff Layton) [683812 629085]- [kdump] kexec: accelerate vmcore copies by marking oldmem in /proc/vmcore as cached (Neil Horman) [683445 641315]- [virt] KVM: VMX: Disallow NMI while blocked by STI (Avi Kivity) [683783 616296]- [virt] kvm: write protect memory after slot swap (Michael S. Tsirkin) [683781 647367][2.6.32-71.19.1.el6]- [crypto] sha-s390: Reset index after processing partial block (Herbert Xu) [678996 626515]- [net] clear heap allocations for privileged ethtool actions (Jiri Pirko) [672434 672435] {CVE-2010-4655}- [usb] iowarrior: don't trust report_size for buffer size (Don Zickus) [672421 672422] {CVE-2010-4656}- [virt] virtio: console: Wake up outvq on host notifications (Amit Shah) [678558 643750]- [fs] inotify: stop kernel memory leak on file creation failure (Eric Paris) [656831 656832] {CVE-2010-4250}- [net] sctp: fix kernel panic resulting from mishandling of icmp dest unreachable msg (Neil Horman) [667028 667029] {CVE-2010-4526}- [mm] install_special_mapping skips security_file_mmap check (Frantisek Hrbata) [662198 662199] {CVE-2010-4346}- [kdump] vt-d: Handle previous faults after enabling fault handling (Takao Indoh) [678485 617137]- [kdump] Enable the intr-remap fault handling after local apic setup (Takao Indoh) [678485 617137]- [kdump] vt-d: Fix the vt-d fault handling irq migration in the x2apic mode (Takao Indoh) [678485 617137]- [kdump] vt-d: Quirk for masking vtd spec errors to platform error handling logic (Takao Indoh) [678485 617137]- [virt] virtio: console: Don't block entire guest if host doesn't read data (Amit Shah) [678562 643751]- [virt] virtio: console: Prevent userspace from submitting NULL buffers (Amit Shah) [678559 635535]- [virt] virtio: console: Fix poll blocking even though there is data to read (Amit Shah) [678561 634232]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0421");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0421.html");
script_cve_id("CVE-2010-3296","CVE-2010-4346","CVE-2010-4526","CVE-2010-4648","CVE-2010-4655","CVE-2010-4656","CVE-2011-0521","CVE-2011-0695","CVE-2011-0710","CVE-2011-0716","CVE-2011-1478");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.24.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

