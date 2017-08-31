# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1106.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122474");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:46:10 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1106");
script_tag(name: "insight", value: "ELSA-2009-1106 -  kernel security and bug fix update - [2.6.18-128.1.14.0.1.el5]- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [MM] balloon code needs to adjust totalhigh_pages (Chuck Anderson) [orabug 8300888][2.6.18-128.1.14.el5]- [nfs] v4: client handling of MAY_EXEC in nfs_permission (Peter Staubach ) [500301 500302] {CVE-2009-1630}- [fs] proc: avoid info leaks to non-privileged processes (Amerigo Wang ) [499546 499541]- [net] tg3: Fix firmware event timeouts (Jiri Pirko ) [502837 481715]- [scsi] libiscsi: fix nop response/reply and session cleanup race (Jiri Pirko ) [502916 497411]- [fs] cifs: fix pointer and checks in cifs_follow_symlink (Jeff Layton ) [496576 496577] {CVE-2009-1633}- [fs] cifs: fix error handling in parse_DFS_referrals (Jeff Layton ) [496576 496577] {CVE-2009-1633}- [fs] cifs: buffer overruns when converting strings (Jeff Layton ) [496576 496577] {CVE-2009-1633}- [fs] cifs: unicode alignment and buffer sizing problems (Jeff Layton ) [494279 494280] {CVE-2009-1439}- [x86] xen: fix local denial of service (Chris Lalancette ) [500950 500951] {CVE-2009-1758}- [misc] compile: add -fwrapv to gcc CFLAGS (Don Zickus ) [501751 491266]- [misc] random: make get_random_int more random (Amerigo Wang ) [499783 499776]- [gfs2] fix uninterruptible quotad sleeping (Steven Whitehouse ) [501742 492943]- [mm] cow vs gup race fix (Andrea Arcangeli ) [486921 471613]- [mm] fork vs gup race fix (Andrea Arcangeli ) [486921 471613]- [nfs] fix hangs during heavy write workloads (Peter Staubach ) [486926 469848][2.6.18-128.1.13.el5]- [misc] add some long-missing capabilities to CAP_FS_MASK (Eric Paris ) [499075 497271 499076 497272] {CVE-2009-1072}- [agp] zero pages before sending to userspace (Jiri Olsa ) [497025 497026] {CVE-2009-1192}- [fs] keep eventpoll from locking up the box (Josef Bacik ) [497322 487585]- [misc] waitpid reports stopped process more than once (Vitaly Mayatskikh ) [486945 481199]- [ata] libata: ahci enclosure management bios workaround (David Milburn ) [500120 488471][2.6.18-128.1.12.el5]- [ia64] fix regression in nanosleep syscall (Prarit Bhargava ) [500349 499289][2.6.18-128.1.11.el5]- [nfs] race with nfs_access_cache_shrinker() and umount (Peter Staubach ) [498653 469225]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1106");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1106.html");
script_cve_id("CVE-2009-1072","CVE-2009-1192","CVE-2009-1439","CVE-2009-1630","CVE-2009-1633","CVE-2009-1758","CVE-2009-3238");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5~1.4.2~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5PAE~1.4.2~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5debug~1.4.2~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.14.0.1.el5xen~1.4.2~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.14.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.14.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.14.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.14.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

