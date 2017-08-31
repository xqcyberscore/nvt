# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0350.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123959");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:50 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0350");
script_tag(name: "insight", value: "ELSA-2012-0350 -  kernel security and bug fix update - [2.6.32-220.7.1.el6]- [netdrv] tg3: Fix single-vector MSI-X code (John Feeney) [787162 703555]- [mm] export remove_from_page_cache() to modules (Jerome Marchand) [772687 751419]- [block] cfq-iosched: fix cfq_cic_link() race confition (Vivek Goyal) [786022 765673]- [fs] cifs: lower default wsize when unix extensions are not used (Jeff Layton) [789058 773705]- [net] svcrpc: fix double-free on shutdown of nfsd after changing pool mode (J. Bruce Fields) [787580 753030]- [net] svcrpc: avoid memory-corruption on pool shutdown (J. Bruce Fields) [787580 753030]- [net] svcrpc: destroy server sockets all at once (J. Bruce Fields) [787580 753030]- [net] svcrpc: simplify svc_close_all (J. Bruce Fields) [787580 753030]- [net] svcrpc: fix list-corrupting race on nfsd shutdown (J. Bruce Fields) [787580 753030]- [fs] xfs: Fix missing xfs_iunlock() on error recovery path in xfs_readlink() (Carlos Maiolino) [749161 694702] {CVE-2011-4077}- [fs] xfs: Fix memory corruption in xfs_readlink (Carlos Maiolino) [749161 694702] {CVE-2011-4077}- [x86] hpet: Disable per-cpu hpet timer if ARAT is supported (Prarit Bhargava) [772884 750201]- [x86] Improve TSC calibration using a delayed workqueue (Prarit Bhargava) [772884 750201]- [kernel] clocksource: Add clocksource_register_hz/khz interface (Prarit Bhargava) [772884 750201]- [kernel] clocksource: Provide a generic mult/shift factor calculation (Prarit Bhargava) [772884 750201]- [block] cfq-iosched: fix a kbuild regression (Vivek Goyal) [769208 705698]- [block] cfq-iosched: rethink seeky detection for SSDs (Vivek Goyal) [769208 705698]- [block] cfq-iosched: rework seeky detection (Vivek Goyal) [769208 705698]- [block] cfq-iosched: don't regard requests with long distance as close (Vivek Goyal) [769208 705698][2.6.32-220.6.1.el6]- [scsi] qla2xxx: Module parameter to control use of async or sync port login (Chad Dupuis) [788003 769007][2.6.32-220.5.1.el6]- [net] igmp: Avoid zero delay when receiving odd mixture of IGMP queries (Jiri Pirko) [772870 772871] {CVE-2012-0207}- [fs] xfs: validate acl count (Eric Sandeen) [773282 773283] {CVE-2012-0038}- [fs] Fix sendfile write-side file position (Steven Whitehouse) [771870 770023]- [virt] kvm: x86: fix missing checks in syscall emulation (Marcelo Tosatti) [773390 773391] {CVE-2012-0045}- [virt] kvm: x86: extend 'struct x86_emulate_ops' with 'get_cpuid' (Marcelo Tosatti) [773390 773391] {CVE-2012-0045}- [fs] nfs: when attempting to open a directory, fall back on normal lookup (Jeff Layton) [771981 755380]- [kernel] crypto: ghash - Avoid null pointer dereference if no key is set (Jiri Benc) [749481 749482] {CVE-2011-4081}- [fs] jbd2: validate sb->s_first in journal_get_superblock() (Eryu Guan) [753344 693981] {CVE-2011-4132}- [net] fix unsafe pointer access in sendmmsg (Jiri Benc) [761668 760798] {CVE-2011-4594}- [scsi] increase qla2xxx firmware ready time-out (Mark Goodwin) [781971 731917]- [perf] powerpc: Handle events that raise an exception without overflowing (Steve Best) [767917 755737] {CVE-2011-4611}- [sched] x86: Avoid unnecessary overflow in sched_clock (Prarit Bhargava) [781974 765720]- [virt] x86: Prevent starting PIT timers in the absence of irqchip support (Marcelo Tosatti) [769634 769550] {CVE-2011-4622}- [virt] vmxnet3: revert hw features change (Neil Horman) [761536 759613]- [netdrv] qlge: fix size of external list for TX address descriptors (Steve Best) [783226 772237]- [netdrv] e1000e: Avoid wrong check on TX hang (Dean Nelson) [768916 751087]- [virt] KVM: Device assignment permission checks (Alex Williamson) [756092 756093] {CVE-2011-4347}- [virt] KVM: Remove ability to assign a device without iommu support (Alex Williamson) [756092 756093] {CVE-2011-4347}- [virt] kvm: device-assignment: revert Disable the option to skip iommu setup (Alex Williamson) [756092 756093] {CVE-2011-4347}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0350");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0350.html");
script_cve_id("CVE-2011-4081","CVE-2011-4347","CVE-2011-4594","CVE-2011-4611","CVE-2012-0038","CVE-2012-0045","CVE-2012-0207","CVE-2011-4077","CVE-2011-4132","CVE-2011-4622");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.7.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

