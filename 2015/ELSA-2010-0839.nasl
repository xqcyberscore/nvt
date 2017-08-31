# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0839.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122298");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:16:14 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0839");
script_tag(name: "insight", value: "ELSA-2010-0839 -  kernel security and bug fix update - [2.6.18-194.26.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb (John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin) [orabug 9504524]- [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [mm] Enhance shrink_zone patch allow full swap utilization, and also be NUMA-aware (John Sobecki, Chris Mason, Herbert van den Bergh) [orabug 9245919]- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346][2.6.18-194.26.1.el5]- [net] mlx4: bump max log_mtts_per_seg memory reservation (Jay Fenlason) [643806 636198][2.6.18-194.25.1.el5]- [fs] nfs: fix regression in NFS Direct I/O path (Steve Dickson) [647601 647297][2.6.18-194.24.1.el5]- Changelog fix[2.6.18-194.23.1.el5]- [net] bonding: correctly process non-linear skbs (Andy Gospodarek) [644822 619070]- Syncing following patch from branched build:- [net] rds: fix local privilege escalation (Eugene Teo) [642897 642898] {CVE-2010-3904}[2.6.18-194.22.1.el5]- [fs] xfs: fix speculative allocation beyond eof (Dave Chinner) [643571 638753][2.6.18-194.21.1.el5]- [scsi] qla2xxx: Correct use-after-free issue in terminate_rport_io callback (Chad Dupuis) [643135 567428]- [misc] futex: replace LOCK_PREFIX in futex.h (Peter Zijlstra) [633175 633176] {CVE-2010-3086}- [v4l] remove compat code for VIDIOCSMICROCODE (Mauro Carvalho Chehab) [642470 642471] {CVE-2010-2963}- [xen] hvm: correct accuracy of pmtimer (Andrew Jones) [641915 633028]- [net] bonding: fix IGMP report on slave during failover (Flavio Leitner) [640973 637764]- [fs] nfsv4: fix bug when server returns NFS4ERR_RESOURCE (Steve Dickson) [628889 620502]- [fs] nfsv4: ensure lockowners are labelled correctly (Steve Dickson) [628889 620502]- [fs] nfsv4: add support for RELEASE_LOCKOWNER operation (Steve Dickson) [628889 620502]- [fs] nfsv4: clean up for lockowner XDR encoding (Steve Dickson) [628889 620502]- [fs] nfsv4: ensure we track lock state in r/w requests (Steve Dickson) [628889 620502]- [time] implement fine grained accounting for PM timer (Ulrich Obergfell) [637069 586285]- [time] initialize tick_nsec based on kernel parameters (Ulrich Obergfell) [637069 586285]- [time] introduce 'pmtimer_fine_grained' kernel parameter (Ulrich Obergfell) [637069 586285]- [fs] nfs: wait for close before silly-renaming (Jeff Layton) [642628 565974][2.6.18-194.20.1.el5]- [scsi] megaraid_sas: fix physical disk handling (Tomas Henzl) [619365 564249]- [scsi] lpfc: fix ioctl crash in lpfc_nlp_put (Rob Evers) [637727 625841]- [net] sched: fix info leak in traffic policing (Neil Horman) [636391 636392] {CVE-2010-3477}- [md] dm: fix deadlock with fsync vs. resize in lvm (Mikulas Patocka) [632255 624068]- [misc] fix race in pid generation causing immediate reuse (Dave Anderson) [638866 634850]- [scsi] fix disk spinup for shorter path restore times (Rob Evers) [634977 608109]- [fs] aio: check for multiplication overflow in io_submit (Jeff Moyer) [629448 629449] {CVE-2010-3067}- [fs] xfs: prevent reading uninitialized stack memory (Dave Chinner) [630806 630807] {CVE-2010-3078}- [fs] aio: fix cleanup in io_submit_one (Jeff Moyer) [631720 631721] {CVE-2010-3066}- [net] ipv4: fix buffer overflow in icmpmsg_put (Frantisek Hrbata) [634976 601391]- [xen] hvm: fix UP suspend/resume/migration w/PV drivers (Miroslav Rezanina) [630989 629773]- [fs] dlm: fix try 1cb failure, part 2 (Abhijith Das) [639073 504188]- [fs] dlm: no node callback when try 1cb lock req fails (David Teigland) [639073 504188][2.6.18-194.19.1.el5]- [virt] xen: fix xennet driver to not corrupt data (Neil Horman) [637220 630129]- [pnp] ignore both UNSET and DISABLED ioresources (Prarit Bhargava) [629861 560540]- [pnp] reserve system board iomem and ioport resources (Prarit Bhargava) [629861 560540]- [net] bonding: fix ALB mode to balance traffic on VLANs (Andy Gospodarek) [630540 578531]- [net] qla3xxx: fix oops on too-long netdev priv structure (Neil Horman) [637206 620508]- [acpi] thinkpad-acpi: lock down video output state access (Don Howard) [629241 607037][2.6.18-194.18.1.el5]- [s390] dasd: fix race between tasklet and dasd_sleep_on (Hendrik Brueckner) [638579 593756]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0839");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0839.html");
script_cve_id("CVE-2010-3066","CVE-2010-3067","CVE-2010-3078","CVE-2010-3086","CVE-2010-3477","CVE-2010-3448");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.26.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.26.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.26.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.26.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.26.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.26.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.26.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.26.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

