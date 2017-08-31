# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-2534.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123612");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:16 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-2534");
script_tag(name: "insight", value: "ELSA-2013-2534 - Unbreakable Enterprise kernel Security update - [2.6.32-400.29.1]- KVM: add missing void __user COPYING CREDITS Documentation Kbuild MAINTAINERS Makefile README REPORTING-BUGS arch block crypto drivers firmware fs include init ipc kernel lib mm net samples scripts security sound tools uek-rpm usr virt cast to access_ok() call (Heiko Carstens) [Orabug: 16941620] {CVE-2013-1943}- KVM: Validate userspace_addr of memslot when registered (Takuya Yoshikawa) [Orabug: 16941620] {CVE-2013-1943}[2.6.32-400.28.1]- do_add_mount()/umount -l races (Jerry Snitselaar) [Orabug: 16311974]- tg3: fix length overflow in VPD firmware parsing (Kees Cook) [Orabug: 16837019] {CVE-2013-1929}- USB: cdc-wdm: fix buffer overflow (Oliver Neukum) [Orabug: 16837003] {CVE-2013-1860}- bonding: emit event when bonding changes MAC (Weiping Pan) [Orabug: 16579025]- sched: Fix ancient race in do_exit() (Joe Jin)- open debug in page_move_anon_rmap by default. (Xiaowei.Hu) [Orabug: 14046035]- block: default SCSI command filter does not accomodate commands overlap across device classes (Jamie Iles) [Orabug: 16387136] {CVE-2012-4542}- vma_adjust: fix the copying of anon_vma chains (Linus Torvalds) [Orabug: 14046035]- xen-netfront: delay gARP until backend switches to Connected (Laszlo Ersek) [Orabug: 16182568]- svcrpc: don't hold sv_lock over svc_xprt_put() (J. Bruce Fields) [Orabug: 16032824]- mm/hotplug: correctly add new zone to all other nodes' zone lists (Jiang Liu) [Orabug: 16603569] {CVE-2012-5517}- ptrace: ptrace_resume() shouldn't wake up !TASK_TRACED thread (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}- Bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Anderson Lizardo) [Orabug: 16711062] {CVE-2013-0349}- dccp: check ccid before dereferencing (Mathias Krause) [Orabug: 16711040] {CVE-2013-1827}- USB: io_ti: Fix NULL dereference in chase_port() (Wolfgang Frisch) [Orabug: 16425435] {CVE-2013-1774}- keys: fix race with concurrent install_user_keyrings() (David Howells) [Orabug: 16493369] {CVE-2013-1792}- KVM: Fix bounds checking in ioapic indirect register reads (CVE-2013-1798) (Andy Honig) [Orabug: 16710937] {CVE-2013-1798}- KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (CVE-2013-1796) (Jerry Snitselaar) [Orabug: 16710794] {CVE-2013-1796}[2.6.32-400.27.1]- net/tun: fix ioctl() based info leaks (Mathias Krause) [Orabug: 16675501] {CVE-2012-6547}- atm: fix info leak via getsockname() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6546}- atm: fix info leak in getsockopt(SO_ATMPVC) (Mathias Krause) [Orabug: 16675501] {CVE-2012-6546}- xfrm_user: fix info leak in copy_to_user_tmpl() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6537}- xfrm_user: fix info leak in copy_to_user_policy() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6537}- xfrm_user: fix info leak in copy_to_user_state() (Mathias Krause) [Orabug: 16675501] {CVE-2013-6537}- xfrm_user: return error pointer instead of NULL #2 (Mathias Krause) [Orabug: 16675501] {CVE-2013-1826}- xfrm_user: return error pointer instead of NULL (Mathias Krause) [Orabug: 16675501] {CVE-2013-1826}- llc: fix info leak via getsockname() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6542}- x86/mm: Check if PUD is large when validating a kernel address (Mel Gorman) [Orabug: 14251997]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-2534");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-2534.html");
script_cve_id("CVE-2012-4542","CVE-2012-6542","CVE-2013-1943","CVE-2013-1929","CVE-2013-1860");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.29.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.29.1.el5uek~1.5.7~2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.29.1.el5uekdebug~1.5.7~2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.29.1.el5uek~1.5.1~4.0.58", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.29.1.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.29.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.29.1.el6uek~1.5.7~0.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.29.1.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.29.1.el6uek~1.5.1~4.0.58", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.29.1.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

