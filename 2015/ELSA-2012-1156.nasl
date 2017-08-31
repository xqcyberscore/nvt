# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1156.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123845");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:09:19 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1156");
script_tag(name: "insight", value: "ELSA-2012-1156 -  kernel security and bug fix update - [2.6.32-279.5.1.el6]- [net] 8021q/vlan: filter device events on bonds (Neil Horman) [842429 841983][2.6.32-279.4.1.el6]- [fs] proc: stats: Use arch_idle_time for idle and iowait times if available (Steve Best) [841579 841149]- [drm] i915: fix integer overflow in i915_gem_execbuffer2() (Jacob Tanenbaum) [824553 824555] {CVE-2012-2383}- [usb] core: change the memory limits in usbfs URB submission (Don Zickus) [841667 828271]- [usb] core: unify some error pathways in usbfs (Don Zickus) [841667 828271]- [netdrv] ixgbe: BIT_APP_UPCHG not set by ixgbe_copy_dcb_cfg() (Andy Gospodarek) [840156 814044]- [netdrv] ixgbe: driver fix for link flap (Andy Gospodarek) [840156 814044]- [net] bridge: Fix enforcement of multicast hash_max limit (Thomas Graf) [840023 832575]- [net] bluetooth: fix sco_conninfo infoleak (Jacob Tanenbaum) [681307 681308] {CVE-2011-1078}- [wireless] ipw2200: remove references to CFG80211_WEXT config option (John Linville) [841406 839311]- [netdrv] be2net: enable GRO by default (Ivan Vecera) [838821 837230]- [virt] kvm/vmx: Fix KVM_SET_SREGS with big real mode segments (Orit Wasserman) [841411 756044]- [fs] writeback: merge for_kupdate and !for_kupdate cases (Eric Sandeen) [832360 818172]- [fs] writeback: fix queue_io() ordering (Eric Sandeen) [832360 818172]- [fs] writeback: don't redirty tail an inode with dirty pages (Eric Sandeen) [832360 818172][2.6.32-279.3.1.el6]- [fs] ext4: properly dirty split extent nodes (David Jeffery) [840052 838640]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1156");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1156.html");
script_cve_id("CVE-2011-1078","CVE-2012-2383");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.5.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

