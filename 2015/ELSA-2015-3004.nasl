# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-3004.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123190");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 09:49:03 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-3004");
script_tag(name: "insight", value: "ELSA-2015-3004 - Unbreakable Enterprise kernel security and bugfix update - [2.6.39-400.246.2]- net: sctp: fix NULL pointer dereference in af->from_addr_param on malformed packet (Daniel Borkmann) [Orabug: 20425333] {CVE-2014-7841}[2.6.39-400.246.1]- sched: Fix possible divide by zero in avg_atom() calculation (Mateusz Guzik) [Orabug: 20148169] - include/linux/math64.h: add div64_ul() (Alex Shi) - deadlock when two nodes are converting same lock from PR to EX and idletimeout closes conn (Tariq Saeed) [Orabug: 18639535] - bonding: Bond master should reflect slave's features. (Ashish Samant) [Orabug: 20231825] - x86, fpu: remove the logic of non-eager fpu mem allocation at the first usage (Annie Li) [Orabug: 20239143] - x86, fpu: remove cpu_has_xmm check in the fx_finit() (Suresh Siddha) [Orabug: 20239143] - x86, fpu: make eagerfpu= boot param tri-state (Suresh Siddha) [Orabug: 20239143] - x86, fpu: enable eagerfpu by default for xsaveopt (Suresh Siddha) [Orabug: 20239143] - x86, fpu: decouple non-lazy/eager fpu restore from xsave (Suresh Siddha) [Orabug: 20239143] - x86, fpu: use non-lazy fpu restore for processors supporting xsave (Suresh Siddha) [Orabug: 20239143] - lguest, x86: handle guest TS bit for lazy/non-lazy fpu host models (Suresh Siddha) [Orabug: 20239143] - x86, fpu: always use kernel_fpu_begin/end() for in-kernel FPU usage (Suresh Siddha) [Orabug: 20239143] - x86, kvm: use kernel_fpu_begin/end() in kvm_load/put_guest_fpu() (Suresh Siddha) [Orabug: 20239143] - x86, fpu: remove unnecessary user_fpu_end() in save_xstate_sig() (Suresh Siddha) [Orabug: 20239143] - raid5: add AVX optimized RAID5 checksumming (Jim Kukunas) [Orabug: 20239143] - x86, fpu: drop the fpu state during thread exit (Suresh Siddha) [Orabug: 20239143] - x32: Add a thread flag for x32 processes (H. Peter Anvin) [Orabug: 20239143] - x86, fpu: Unify signal handling code paths for x86 and x86_64 kernels (Suresh Siddha) [Orabug: 20239143] - x86, fpu: Consolidate inline asm routines for saving/restoring fpu state (Suresh Siddha) [Orabug: 20239143] - x86, signal: Cleanup ifdefs and is_ia32, is_x32 (Suresh Siddha) [Orabug: 20239143] into exported and internal interfaces (Linus Torvalds) [Orabug: 20239143] - i387: Uninline the generic FP helpers that we expose to kernel modules (Linus Torvalds) [Orabug: 20239143] - i387: use 'restore_fpu_checking()' directly in task switching code (Linus Torvalds) [Orabug: 20239143] - i387: fix up some fpu_counter confusion (Linus Torvalds) [Orabug: 20239143]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-3004");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-3004.html");
script_cve_id("CVE-2014-7841");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.246.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.246.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.246.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.246.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.246.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.246.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.246.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.246.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.246.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.246.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.246.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.246.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

