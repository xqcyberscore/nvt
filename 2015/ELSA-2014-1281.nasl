# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1281.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123305");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1281");
script_tag(name: "insight", value: "ELSA-2014-1281 -  kernel security and bug fix update - [3.10.0-123.8.1]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-123.8.1]- [scsi] fnic: fix broken FIP discovery by initializing multicast address (Chris Leech) [1119727 1100078]- [scsi] libfcoe: Make fcoe_sysfs optional / fix fnic NULL exception (Chris Leech) [1119727 1100078]- [fs] nfs: Don't mark the data cache as invalid if it has been flushed (Scott Mayhew) [1115817 1114054]- [fs] nfs: Clear NFS_INO_REVAL_PAGECACHE when we update the file size (Scott Mayhew) [1115817 1114054]- [fs] nfs: Fix cache_validity check in nfs_write_pageuptodate() (Scott Mayhew) [1115817 1114054]- [mm] hugetlb: ensure hugepage access is denied if hugepages are not supported (David Gibson) [1122115 1081671]- [kernel] hrtimer: Prevent all reprogramming if hang detected (Prarit Bhargava) [1113175 1094732][3.10.0-123.7.1]- [scsi] set DID_TIME_OUT correctly (Ewan Milne) [1122575 1103881]- [scsi] fix invalid setting of host byte (Ewan Milne) [1122575 1103881]- [scsi] More USB deadlock fixes (Ewan Milne) [1122575 1103881]- [scsi] Fix USB deadlock caused by SCSI error handling (Ewan Milne) [1122575 1103881]- [scsi] Fix command result state propagation (Ewan Milne) [1122575 1103881]- [scsi] Fix spurious request sense in error handling (Ewan Milne) [1122575 1103881]- [input] synaptics: fix resolution for manually provided min/max (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: change min/max quirk table to pnp-id matching (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: add a matches_pnp_id helper function (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: T540p - unify with other LEN0034 models (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: add min/max quirk for the ThinkPad W540 (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: add min/max quirk for ThinkPad Edge E431 (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: add min/max quirk for ThinkPad T431s, L440, L540, S1 Yoga and X1 (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: report INPUT_PROP_TOPBUTTONPAD property (Benjamin Tissoires) [1122559 1093449]- [input] Add INPUT_PROP_TOPBUTTONPAD device property (Benjamin Tissoires) [1122559 1093449]- [input] i8042: add firmware_id support (Benjamin Tissoires) [1122559 1093449]- [input] serio: add firmware_id sysfs attribute (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: add manual min/max quirk for ThinkPad X240 (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: add manual min/max quirk (Benjamin Tissoires) [1122559 1093449]- [input] synaptics: fix incorrect placement of __initconst (Benjamin Tissoires) [1122559 1093449]- [ethernet] be2net: Fix invocation of be_close() after be_clear() (Ivan Vecera) [1122558 1066644]- [ethernet] be2net: enable interrupts in EEH resume (Ivan Vecera) [1121712 1076682]- [ethernet] sfc: PIO:Restrict to 64bit arch and use 64-bit writes (Nikolay Aleksandrov) [1119725 1089024]- [kernel] ftrace: Hardcode ftrace_module_init() call into load_module() (Takahiro MUNEDA) [1119721 1061553]- [kernel] trace: Make register/unregister_ftrace_command __init (Takahiro MUNEDA) [1119721 1061553]- [block] nvme: Initialize device reference count earlier (David Milburn) [1119720 1081734]- [ata] ahci: accommodate tag ordered controller (David Milburn) [1117154 1083746]- [s390] af_iucv: recvmsg problem for SOCK_STREAM sockets (Hendrik Brueckner) [1115585 1109703]- [s390] af_iucv: correct cleanup if listen backlog is full (Hendrik Brueckner) [1115584 1109033]- [mm] Revert: vmscan: do not swap anon pages just because free+file is low (Johannes Weiner) [1114938 1102991]- [drm] nouveau/bios: fix a bit shift error introduced by recent commit (Ulrich Obergfell) [1114869 1089936]- [ethernet] bnx2x: Adapter not recovery from EEH error injection (Michal Schmidt) [1107722 1067154]- [kernel] auditsc: audit_krule mask accesses need bounds checking (Denys Vlasenko) [1102708 1102710] {CVE-2014-3917}- [block] mtip32xx: mtip_async_complete() bug fixes (Jeff Moyer) [1125776 1102281]- [block] mtip32xx: Unmap the DMA segments before completing the IO request (Jeff Moyer) [1125776 1102281]- [net] l2tp: don't fall back on UDP [get or set]sockopt (Petr Matousek) [1119465 1119466] {CVE-2014-4943}- [s390] ptrace: correct insufficient sanitization when setting psw mask (Hendrik Brueckner) [1114090 1113673] {CVE-2014-3534}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1281");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1281.html");
script_cve_id("CVE-2014-3917");
script_tag(name:"cvss_base", value:"3.3");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.8.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

