# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0498.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122179");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:20 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0498");
script_tag(name: "insight", value: "ELSA-2011-0498 -  kernel security, bug fix, and enhancement update - [2.6.32-71.29.1.el6]- [mm] Revert '[mm] pdpte registers are not flushed when PGD entry is changed in x86 PAE mode' (Larry Woodman) [695256 691310][2.6.32-71.28.1.el6]- [net] bonding: fix jiffy comparison issues (Andy Gospodarek) [698109 696337]- [drm] radeon/kms: check AA resolve registers on r300 + regression fix (Dave Airlie) [680001 680002] {CVE-2011-1016}- [infiniband] uverbs: Handle large number of entries in poll CQ (Eugene Teo) [688429 696137] {CVE-2011-1044 CVE-2010-4649}- [net] sctp: fix the INIT/INIT-ACK chunk length calculation (Thomas Graf) [695386 690743] {CVE-2011-1573}- [net] CAN: Use inode instead of kernel address for /proc file (Danny Feng) [664560 664561] {CVE-2010-4565}- [fs] inotify: fix double free/corruption of stuct user (Eric Paris) [656831 656832] {CVE-2010-4250}- [net] netfilter: ipt_CLUSTERIP: fix buffer overflow (Jiri Pirko) [689341 689342]- [net] bonding: change test for presence of VLANs (Jiri Pirko) [696487 683496]- [scsi] scsi_dh: fix reference counting in scsi_dh_activate error path (Mike Snitzer) [696889 680140]- [net] enable VLAN NULL tagging (Neil Horman) [683810 633571]- [scsi] scsi_dh: propagate SCSI device deletion (Mike Snitzer) [698114 669411]- [fs] inotify: stop kernel memory leak on file creation failure (Eric Paris) [656831 656832] {CVE-2010-4250}[2.6.32-71.27.1.el6]- [scsi] megaraid: give FW more time to recover from reset (Tomas Henzl) [695322 692673]- [netdrv] ixgbe: fix for 82599 erratum on Header Splitting (Andy Gospodarek) [683820 669231]- [sound] ALSA: hda - nvhdmi: Add missing codec IDs, unify names (Jaroslav Kysela) [683817 636922]- [mm] pdpte registers are not flushed when PGD entry is changed in x86 PAE mode (Larry Woodman) [695256 691310]- [net] fix ebtables stack infoleak (Eugene Teo) [681322 681323] {CVE-2011-1080}- [drm] fix unsigned vs signed comparison issue in modeset ctl ioctl (Don Howard) [679927 679928] {CVE-2011-1013}- [pci] Enable ASPM state clearing regardless of policy (Alex Williamson) [694073 681017]- [pci] Disable ASPM if BIOS asks us to (Alex Williamson) [694073 681017]- [mm] do not keep kswapd awake for an unreclaimable zone (Johannes Weiner) [694186 633825][2.6.32-71.26.1.el6]- [net] bnep: fix buffer overflow (Don Howard) [681315 681316] {CVE-2011-1079}- [scsi] aic94xx: world-writable sysfs update_bios file (Don Howard) [679306 679307]- [x86] tc1100-wmi: world-writable sysfs wireless and jogdial files (Don Howard) [679306 679307]- [x86] acer-wmi: world-writable sysfs threeg file (Don Howard) [679306 679307]- [mfd] ab3100: world-writable debugfs *_priv files (Don Howard) [679306 679307]- [v4l] sn9c102: world-wirtable sysfs files (Don Howard) [679306 679307]- [x86] Fix EFI pagetable to map whole memory (Takao Indoh) [670850 664364]- [kernel] CAP_SYS_MODULE bypass via CAP_NET_ADMIN (Phillip Lougher) [681772 681773] {CVE-2011-1019}- [kernel] failure to revert address limit override in OOPS error path (Dave Anderson) [659572 659573] {CVE-2010-4258}- [fs] xfs: zero proper structure size for geometry calls (Phillip Lougher) [677267 677268] {CVE-2011-0711}- [fs] xfs: prevent leaking uninitialized stack memory in FSGEOMETRY_V1 (Phillip Lougher) [677267 677268] {CVE-2011-0711}- [tty] tty_audit: fix tty_audit_add_data live lock on audit disabled (Danny Feng) [684275 680126]- [kernel] proc: protect mm start_code/end_code in /proc/pid/stat (Eugene Teo) [684572 684573] {CVE-2011-0726}- [net] dccp oops (Eugene Teo) [682957 682958] {CVE-2011-1093}- [firmware] dcdbas: force SMI to happen when expected (Shyam Iyer) [683440 664832]- [security] ima: fix add LSM rule bug (Eric Paris) [667914 667915] {CVE-2011-0006}- [sound] caiaq: Fix possible string buffer overflow (Jaroslav Kysela) [678475 678476] {CVE-2011-0712}- [net] ixgbe: add option to control interrupt mode (Andy Gospodarek) [670114 670110 622640 637332][2.6.32-71.25.1.el6]- [net] bridge: do not learn from exact matches (Jiri Pirko) [691777 623199]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0498");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0498.html");
script_cve_id("CVE-2010-4250","CVE-2010-4565","CVE-2010-4649","CVE-2011-0006","CVE-2011-0711","CVE-2011-0712","CVE-2011-0726","CVE-2011-1013","CVE-2011-1016","CVE-2011-1019","CVE-2011-1044","CVE-2011-1079","CVE-2011-1080","CVE-2011-1093","CVE-2011-1573");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.29.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

