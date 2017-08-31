# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0185.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122884");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-02-18 07:27:24 +0200 (Thu, 18 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0185");
script_tag(name: "insight", value: "ELSA-2016-0185 -  kernel security and bug fix update - - [3.10.0-327.10.1.OL7]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-327.10.1]- [of] return NUMA_NO_NODE from fallback of_node_to_nid() (Thadeu Lima de Souza Cascardo) [1300614 1294398]- [net] openvswitch: do not allocate memory from offline numa node (Thadeu Lima de Souza Cascardo) [1300614 1294398][3.10.0-327.9.1]- [security] keys: Fix keyring ref leak in join_session_keyring() (David Howells) [1298931 1298036] {CVE-2016-0728}[3.10.0-327.8.1]- [md] dm: fix AB-BA deadlock in __dm_destroy() (Mike Snitzer) [1296566 1292481]- [md] revert 'dm-mpath: fix stalls when handling invalid ioctls' (Mike Snitzer) [1287552 1277194]- [cpufreq] intel_pstate: Fix limits->max_perf rounding error (Prarit Bhargava) [1296276 1279617]- [cpufreq] intel_pstate: Fix limits->max_policy_pct rounding error (Prarit Bhargava) [1296276 1279617]- [cpufreq] revert 'intel_pstate: fix rounding error in max_freq_pct' (Prarit Bhargava) [1296276 1279617]- [crypto] nx: 842 - Add CRC and validation support (Gustavo Duarte) [1289451 1264905]- [powerpc] eeh: More relaxed condition for enabled IO path (Steve Best) [1289101 1274731]- [security] keys: Don't permit request_key() to construct a new keyring (David Howells) [1275929 1273465] {CVE-2015-7872}- [security] keys: Fix crash when attempt to garbage collect an uninstantiated keyring (David Howells) [1275929 1273465] {CVE-2015-7872}- [security] keys: Fix race between key destruction and finding a keyring by name (David Howells) [1275929 1273465] {CVE-2015-7872}- [x86] paravirt: Replace the paravirt nop with a bona fide empty function (Mateusz Guzik) [1259582 1259583] {CVE-2015-5157}- [x86] nmi: Fix a paravirt stack-clobbering bug in the NMI code (Mateusz Guzik) [1259582 1259583] {CVE-2015-5157}- [x86] nmi: Use DF to avoid userspace RSP confusing nested NMI detection (Mateusz Guzik) [1259582 1259583] {CVE-2015-5157}- [x86] nmi: Reorder nested NMI checks (Mateusz Guzik) [1259582 1259583] {CVE-2015-5157}- [x86] nmi: Improve nested NMI comments (Mateusz Guzik) [1259582 1259583] {CVE-2015-5157}- [x86] nmi: Switch stacks on userspace NMI entry (Mateusz Guzik) [1259582 1259583] {CVE-2015-5157}[3.10.0-327.7.1]- [scsi] scsi_sysfs: protect against double execution of __scsi_remove_device() (Vitaly Kuznetsov) [1292075 1273723]- [powerpc] mm: Recompute hash value after a failed update (Gustavo Duarte) [1289452 1264920]- [misc] genwqe: get rid of atomic allocations (Hendrik Brueckner) [1289450 1270244]- [mm] use only per-device readahead limit (Eric Sandeen) [1287550 1280355]- [net] ipv6: update ip6_rt_last_gc every time GC is run (Hannes Frederic Sowa) [1285370 1270092]- [kernel] tick: broadcast: Prevent livelock from event handler (Prarit Bhargava) [1284043 1265283]- [kernel] clockevents: Serialize calls to clockevents_update_freq() in the core (Prarit Bhargava) [1284043 1265283][3.10.0-327.6.1]- [netdrv] bonding: propagate LRO disable to slave devices (Jarod Wilson) [1292072 1266578][3.10.0-327.5.1]- [net] vsock: Fix lockdep issue (Dave Anderson) [1292372 1253971]- [net] vsock: sock_put wasn't safe to call in interrupt context (Dave Anderson) [1292372 1253971]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0185");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0185.html");
script_cve_id("CVE-2015-7872","CVE-2015-5157");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.10.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

