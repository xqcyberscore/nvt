# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1534.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123040");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:35 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1534");
script_tag(name: "insight", value: "ELSA-2015-1534 -  kernel security and bug fix update - [3.10.0-229.11.1]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-229.11.1]- [fs] Fixing lease renewal (Steve Dickson) [1226328 1205048]- [fs] revert 'nfs: Fixing lease renewal' (Carlos Maiolino) [1226328 1205048]- [redhat] spec: Update dracut dependency to 033-241. or ael7b]_1.5 (Phillip Lougher) [1241571 1241344][3.10.0-229.10.1]- [redhat] spec: Update dracut dependency to pull in drbg module (Phillip Lougher) [1241571 1241344][3.10.0-229.9.1]- [crypto] krng: Remove krng (Herbert Xu) [1238210 1229738]- [crypto] drbg: Add stdrng alias and increase priority (Herbert Xu) [1238210 1229738]- [crypto] seqiv: Move IV seeding into init function (Herbert Xu) [1238210 1229738]- [crypto] eseqiv: Move IV seeding into init function (Herbert Xu) [1238210 1229738]- [crypto] chainiv: Move IV seeding into init function (Herbert Xu) [1238210 1229738]- [s390] crypto: ghash - Fix incorrect ghash icv buffer handling (Herbert Xu) [1238211 1207598]- [kernel] module: Call module notifier on failure after complete_formation() (Bandan Das) [1238937 1236273]- [net] ipv4: kABI fix for 0bbf87d backport (Aristeu Rozanski) [1238208 1184764]- [net] ipv4: Convert ipv4.ip_local_port_range to be per netns (Aristeu Rozanski) [1238208 1184764]- [of] Eliminate of_allnodes list (Gustavo Duarte) [1236983 1210533]- [scsi] ipr: Increase default adapter init stage change timeout (Steve Best) [1236139 1229217]- [fs] libceph: fix double __remove_osd() problem (Sage Weil) [1236462 1229488]- [fs] ext4: fix data corruption caused by unwritten and delayed extents (Lukas Czerner) [1235563 1213487]- [kernel] watchdog: update watchdog_thresh properly (Ulrich Obergfell) [1223924 1216074]- [kernel] watchdog: update watchdog attributes atomically (Ulrich Obergfell) [1223924 1216074]- [virt] kvm: ensure hard lockup detection is disabled by default (Andrew Jones) [1236461 1111262]- [watchdog] control hard lockup detection default (Andrew Jones) [1236461 1111262]- [watchdog] Fix print-once on enable (Andrew Jones) [1236461 1111262][3.10.0-229.8.1]- [fs] fs-cache: The retrieval remaining-pages counter needs to be atomic_t (David Howells) [1231809 1130457]- [net] libceph: tcp_nodelay support (Sage Weil) [1231803 1197952]- [powerpc] pseries: Simplify check for suspendability during suspend/migration (Gustavo Duarte) [1231638 1207295]- [powerpc] pseries: Introduce api_version to migration sysfs interface (Gustavo Duarte) [1231638 1207295]- [powerpc] pseries: Little endian fixes for post mobility device tree update (Gustavo Duarte) [1231638 1207295]- [fs] sunrpc: Add missing support for RPC_CLNT_CREATE_NO_RETRANS_TIMEOUT (Steve Dickson) [1227825 1111712]- [fs] nfs: Fixing lease renewal (Benjamin Coddington) [1226328 1205048]- [powerpc] iommu: ddw: Fix endianness (Steve Best) [1224406 1189040]- [usb] fix use-after-free bug in usb_hcd_unlink_urb() (Don Zickus) [1223239 1187256]- [net] ipv4: Missing sk_nulls_node_init() in ping_unhash() (Denys Vlasenko) [1218104 1218105] {CVE-2015-3636}- [net] nf_conntrack: reserve two bytes for nf_ct_ext->len (Marcelo Leitner) [1211096 1206164] {CVE-2014-9715}- [net] ipv6: Don't reduce hop limit for an interface (Denys Vlasenko) [1208494 1208496] {CVE-2015-2922}- [x86] kernel: execution in the early microcode loader (Jacob Tanenbaum) [1206829 1206830] {CVE-2015-2666}- [fs] pipe: fix pipe corruption and iovec overrun on partial copy (Seth Jennings) [1202861 1198843] {CVE-2015-1805}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1534");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1534.html");
script_cve_id("CVE-2015-2922","CVE-2015-3636","CVE-2014-9715","CVE-2015-2666");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.11.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

