# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2552.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122797");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-12-09 06:54:00 +0200 (Wed, 09 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2552");
script_tag(name: "insight", value: "ELSA-2015-2552 -  kernel security and bug fix update - [3.10.0-327.3.1.OL7]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-327.3.1]- rebuild[3.10.0-327.2.1]- [netdrv] macvtap: unbreak receiving of gro skb with frag list (Jason Wang) [1279794 1273737]- [net] ipv6: drop frames with attached skb->sk in forwarding (Hannes Frederic Sowa) [1281701 1243966]- [net] ipv6: ip6_forward: perform skb->pkt_type check at the beginning (Hannes Frederic Sowa) [1281701 1243966]- [net] sctp: Fix race between OOTB responce and route removal (Jamie Bainbridge) [1281426 1277309]- [x86] mm: fix VM_FAULT_RETRY handling (Andrea Arcangeli) [1281427 1277226]- [x86] mm: consolidate VM_FAULT_RETRY handling (Andrea Arcangeli) [1281427 1277226]- [x86] mm: move mmap_sem unlock from mm_fault_error() to caller (Andrea Arcangeli) [1281427 1277226]- [mm] let mm_find_pmd fix buggy race with THP fault (Larry Woodman) [1281424 1273993]- [mm] ksm: unstable_tree_search_insert error checking cleanup (Andrea Arcangeli) [1281422 1274871]- [mm] ksm: use find_mergeable_vma in try_to_merge_with_ksm_page (Andrea Arcangeli) [1281422 1274871]- [mm] ksm: use the helper method to do the hlist_empty check (Andrea Arcangeli) [1281422 1274871]- [mm] ksm: don't fail stable tree lookups if walking over stale stable_nodes (Andrea Arcangeli) [1281422 1274871]- [mm] ksm: add cond_resched() to the rmap_walks (Andrea Arcangeli) [1281422 1274871]- [powerpc] kvm: book3s_hv: Synthesize segment fault if SLB lookup fails (Thomas Huth) [1281423 1269467]- [powerpc] kvm: book3s_hv: Create debugfs file for each guest's HPT (David Gibson) [1281420 1273692]- [powerpc] kvm: book3s_hv: Add helpers for lock/unlock hpte (David Gibson) [1281420 1273692]- [powerpc] pci: initialize hybrid_dma_data before use (Laurent Vivier) [1279793 1270717]- [md] raid10: don't clear bitmap bit when bad-block-list write fails (Jes Sorensen) [1279796 1267652]- [md] raid1: don't clear bitmap bit when bad-block-list write fails (Jes Sorensen) [1279796 1267652]- [md] raid10: submit_bio_wait() returns 0 on success (Jes Sorensen) [1279796 1267652]- [md] raid1: submit_bio_wait() returns 0 on success (Jes Sorensen) [1279796 1267652]- [md] crash in md-raid1 and md-raid10 due to incorrect list manipulation (Jes Sorensen) [1279796 1267652]- [md] raid10: ensure device failure recorded before write request returns (Jes Sorensen) [1279796 1267652]- [md] raid1: ensure device failure recorded before write request returns (Jes Sorensen) [1279796 1267652]- [block] nvme: Fix memory leak on retried commands (David Milburn) [1279792 1271860]- [cpufreq] intel_pstate: fix rounding error in max_freq_pct (Prarit Bhargava) [1281491 1263866]- [cpufreq] intel_pstate: fix PCT_TO_HWP macro (Prarit Bhargava) [1273926 1264990]- [cpufreq] revert 'intel_pstate: add quirk to disable HWP on Skylake-S processors' (Prarit Bhargava) [1273926 1264990]- [cpufreq] revert 'intel_pstate: disable Skylake processors' (Prarit Bhargava) [1273926 1264990]- [x86] kvm: svm: unconditionally intercept #DB (Paolo Bonzini) [1279469 1279470] {CVE-2015-8104}- [x86] virt: guest to host DoS by triggering an infinite loop in microcode (Paolo Bonzini) [1277560 1277561] {CVE-2015-5307}[3.10.0-327.1.1]- [x86] kvm: mmu: fix validation of mmio page fault (Bandan Das) [1275150 1267128]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2552");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2552.html");
script_cve_id("CVE-2015-5307","CVE-2015-8104");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.3.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

