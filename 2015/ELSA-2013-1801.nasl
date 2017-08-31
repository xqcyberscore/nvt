# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1801.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123497");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:39 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1801");
script_tag(name: "insight", value: "ELSA-2013-1801 -  kernel security, bug fix, and enhancement update - [2.6.32-431.1.2]- [x86] kvm: fix cross page vapic_addr access (Paolo Bonzini) [1032214 1032215] {CVE-2013-6368}- [x86] kvm: fix division by zero in apic_get_tmcct (Paolo Bonzini) [1032212 1032213] {CVE-2013-6367}[2.6.32-431.1.1]- [netdrv] mlx4_en: Check device state when setting coalescing (Amir Vadai) [1032395 975908]- [net] ip_output: do skb ufo init for peeked non ufo skb as well (Jiri Pirko) [1023490 1023491] {CVE-2013-4470}- [net] ip6_output: do skb ufo init for peeked non ufo skb as well (Jiri Pirko) [1023490 1023491] {CVE-2013-4470}- [net] sunrpc: Fix a data corruption issue when retransmitting RPC calls (Jeff Layton) [1032424 1030046]- [fs] gfs2: Implement a rgrp has no extents longer than X scheme (Robert S Peterson) [1032162 998625]- [fs] gfs2: Drop inadequate rgrps from the reservation tree (Robert S Peterson) [1032162 998625]- [fs] gfs2: If requested is too large, use the largest extent in the rgrp (Robert S Peterson) [1032162 998625]- [fs] gfs2: Add allocation parameters structure (Robert S Peterson) [1032162 998625]- [fs] nfs: Don't check lock owner compatability unless file is locked - part 2 (Jeff Layton) [1032260 1007039]- [fs] nfs: Don't check lock owner compatibility in writes unless file is locked (Jeff Layton) [1032260 1007039]- [netdrv] ixgbevf: move API neg to reset path (Andy Gospodarek) [1032168 1019346]- [netdrv] ixgbe: fix inconsistent clearing of the multicast table (Andy Gospodarek) [1032170 975248]- [mm] Group e820 entries together and add map_individual_e820 boot option (Larry Woodman) [1020518 876275]- [mm] Exclude E820_RESERVED regions and memory holes above 4 GB from direct mapping (Larry Woodman) [1020518 876275]- [mm] Find_early_table_space based on ranges that are actually being mapped (Larry Woodman) [1020518 876275]- [fs] nfs: Fix the sync mount option for nfs4 mounts (Scott Mayhew) [1030171 915862]- [fs] nfsv4: Missing Chunk of Back Port Patch Causes Hang (Steve Dickson) [1032250 1024006]- [fs] xfs: Ensure sync updates the log tail correctly (Dave Chinner) [1032249 1025439]- [fs] xfs: only update the last_sync_lsn when a transaction completes (Dave Chinner) [1032249 1025439]- [fs] xfs: prevent deadlock trying to cover an active log (Dave Chinner) [1032688 1014867]- [kernel] signal: stop info leak via the tkill and the tgkill syscalls (Petr Holasek) [970876 970878] {CVE-2013-2141}- [block] rsxx: Disallow discards from being unmapped (Steve Best) [1028278 1023897]- [netdrv] brcmsmac: Module alias support missing from backport (John Green) [1029330 1020461]- [netdrv] mlx4_en: Fix pages never dma unmapped on rx (Steve Best) [1027343 1023272]- [netdrv] mlx4_en: Fix BlueFlame race (Amir Vadai) [1029997 987634]- [scsi] lpfc 8.3.42: Fixed failure to allocate SCSI buffer on PPC64 platform for SLI4 devices (Rob Evers) [1030713 1024683]- [scsi] Revert: qla2xxx: Ramp down queue depth for attached SCSI devices when driver resources are low. [1032167 995576]- [netdrv] tg3: avoid double-freeing of rx data memory (Ivan Vecera) [1032423 1020685]- [hda] alsa: Final fix for the Haswell HDMI audio 44.1kHz rate (Jaroslav Kysela) [1032247 1024548]- [input] wacom: do not report ABS_MISC on TPC2FG touch device (Aristeu Rozanski) [1032426 1032256]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1801");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1801.html");
script_cve_id("CVE-2013-2141","CVE-2013-4470","CVE-2013-6367","CVE-2013-6368");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.1.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

