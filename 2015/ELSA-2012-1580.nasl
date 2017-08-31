# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1580.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123769");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:18 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1580");
script_tag(name: "insight", value: "ELSA-2012-1580 -  kernel security, bug fix and enhancement update - [2.6.32-279.19.1.el6]- [drm] i915: dont clobber the pipe param in sanitize_modesetting (Frantisek Hrbata) [876549 857792]- [drm] i915: Sanitize BIOS debugging bits from PIPECONF (Frantisek Hrbata) [876549 857792]- [net] fix divide by zero in tcp algorithm illinois (Flavio Leitner) [871920 866514] {CVE-2012-4565}- [fs] xfs: fix reading of wrapped log data (Dave Chinner) [876499 874322]- [x86] mm: fix signedness issue in mmap_rnd() (Petr Matousek) [876496 875036]- [net] WARN if struct ip_options was allocated directly by kmalloc (Jiri Pirko) [877950 872799]- [fs] block_dev: Fix crash when block device is read and block size is changed at the same time (Frantisek Hrbata) [864826 855906]- [mm] tracing: Move include of trace/events/kmem.h out of header into slab.c (Jeff Moyer) [864826 855906]- [mm] slab: Move kmalloc tracepoint out of inline code (Jeff Moyer) [864826 855906]- [netdrv] bnx2x: organize BDs calculation for stop/resume (Frantisek Hrbata) [874022 819842]- [netdrv] bnx2x: fix panic when TX ring is full (Michal Schmidt) [874022 819842][2.6.32-279.18.1.el6]- [scsi] sd: fix crash when UA received on DIF enabled device (Ewan Milne) [876487 865682]- [mm] hugetlb: fix non-atomic enqueue of huge page (Rafael Aquini) [876101 869750]- [x86] amd_iommu: attach device fails on the last pci device (Don Dutile) [876493 861164]- [net] nfs: Fix buffer overflow checking in __nfs4_get_acl_uncached (Frantisek Hrbata) [811794 822871] {CVE-2012-2375}- [net] nfs: Fix the acl cache size calculation (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] nfs: Fix range checking in __nfs4_get_acl_uncached and __nfs4_proc_set_acl (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] nfs: nfs_getaclargs.acl_len is a size_t (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] nfs: Dont use private xdr_stream fields in decode_getacl (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] nfs: Fix pointer arithmetic in decode_getacl (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] nfs: Simplify the GETATTR attribute length calculation (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] sunrpc: Add the helper xdr_stream_pos (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] sunrpc: Dont decode beyond the end of the RPC reply message (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] sunrpc: Clean up xdr_set_iov() (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [net] sunrpc: xdr_read_pages needs to clear xdr->page_ptr (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [fs] nfs: Avoid beyond bounds copy while caching ACL (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [fs] nfs: Avoid reading past buffer when calling GETACL (Sachin Prabhu) [811794 822871] {CVE-2012-2375}- [scsi] ibmvfc: Fix double completion on abort timeout (Steve Best) [876088 865115]- [net] core: allocate skbs on local node (Andy Gospodarek) [876491 843163][2.6.32-279.17.1.el6]- [mm] Prevent kernel panic in NUMA related system calls after memory hot-add (Larry Woodman) [875382 870350] {CVE-2012-5517}- [md] Dont truncate size at 4TB for RAID0 and Linear (Jes Sorensen) [866470 865637]- [fs] ext4: fix undefined bit shift result in ext4_fill_flex_info (Lukas Czerner) [809690 809691] {CVE-2012-2100}- [fs] ext4: fix undefined behavior in ext4_fill_flex_info() (Lukas Czerner) [809690 809691] {CVE-2012-2100}- [kernel] sched_rt: Ignore RT queue throttling if idle task has RT policy (Igor Mammedov) [853950 843541]- [kernel] sched: Create special class for stop/migrate work (Igor Mammedov) [853950 843541]- [net] ipv6: fix overlap check for fragments (Amerigo Wang) [874550 819952] {CVE-2012-4444}- [net] ipv6: discard overlapping fragment (Jiri Pirko) [874550 819952] {CVE-2012-4444}[2.6.32-279.16.1.el6]- [lib] Fix rwsem to not hang the system (David Howells) [871854 852847][2.6.32-279.15.1.el6]- [netdrv] mlx4: Re-design multicast attachments flow (Doug Ledford) [866795 859533]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1580");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1580.html");
script_cve_id("CVE-2012-2100","CVE-2012-2375","CVE-2012-4444","CVE-2012-4565","CVE-2012-5517");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.19.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

