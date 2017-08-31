# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-2520.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123636");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:35 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-2520");
script_tag(name: "insight", value: "ELSA-2013-2520 - Unbreakable Enterprise kernel security update - [2.6.32-400.26.2]- mm/hotplug: correctly add new zone to all other nodes' zone lists (Jiang Liu) [Orabug: 16603569] {CVE-2012-5517}- ptrace: ptrace_resume() shouldn't wake up !TASK_TRACED thread (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}- Bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Anderson Lizardo) [Orabug: 16711062] {CVE-2013-0349}- dccp: check ccid before dereferencing (Mathias Krause) [Orabug: 16711040] {CVE-2013-1827}- USB: io_ti: Fix NULL dereference in chase_port() (Wolfgang Frisch) [Orabug: 16425435] {CVE-2013-1774}- keys: fix race with concurrent install_user_keyrings() (David Howells) [Orabug: 16493369] {CVE-2013-1792}- KVM: Fix bounds checking in ioapic indirect register reads (CVE-2013-1798) (Andy Honig) [Orabug: 16710937] {CVE-2013-1798}- KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (CVE-2013-1796) (Jerry Snitselaar) [Orabug: 16710794] {CVE-2013-1796}- net/tun: fix ioctl() based info leaks (Mathias Krause) [Orabug: 16675501] {CVE-2012-6547}- atm: fix info leak via getsockname() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6546}- atm: fix info leak in getsockopt(SO_ATMPVC) (Mathias Krause) [Orabug: 16675501] {CVE-2012-6546}- xfrm_user: fix info leak in copy_to_user_tmpl() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6537}- xfrm_user: fix info leak in copy_to_user_policy() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6537}- xfrm_user: fix info leak in copy_to_user_state() (Mathias Krause) [Orabug: 16675501] {CVE-2013-6537}- xfrm_user: return error pointer instead of NULL #2 (Mathias Krause) [Orabug: 16675501] {CVE-2013-1826}- xfrm_user: return error pointer instead of NULL (Mathias Krause) [Orabug: 16675501] {CVE-2013-1826}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-2520");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-2520.html");
script_cve_id("CVE-2012-4508","CVE-2012-5517","CVE-2013-0309","CVE-2013-0310","CVE-2013-0871","CVE-2013-1796","CVE-2013-1798","CVE-2012-6537","CVE-2012-6546","CVE-2012-6547","CVE-2013-1826","CVE-2013-0349","CVE-2013-1774","CVE-2013-1792","CVE-2013-1827");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.26.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.26.2.el5uek~1.5.7~2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.26.2.el5uekdebug~1.5.7~2", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.26.2.el5uek~1.5.1~4.0.58", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.26.2.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.26.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.26.2.el6uek~1.5.7~0.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mlnx_en", rpm:"mlnx_en~2.6.32~400.26.2.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.26.2.el6uek~1.5.1~4.0.58", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~400.26.2.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

