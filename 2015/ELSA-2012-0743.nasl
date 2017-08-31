# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0743.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123900");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0743");
script_tag(name: "insight", value: "ELSA-2012-0743 -  kernel security and bug fix update - [2.6.32-220.23.1.el6]- [net] bond: Make LRO flag follow slave settings (Neil Horman) [831176 794647][2.6.32-220.22.1.el6]- [net] ipv4/netfilter: TCP and raw fix for ip_route_me_harder (Jiri Benc) [824429 812108][2.6.32-220.21.1.el6]- [security] fix compile error in commoncap.c (Eric Paris) [806725 806726] {CVE-2012-2123}- [security] fcaps: clear the same personality flags as suid when fcaps are used (Eric Paris) [806725 806726] {CVE-2012-2123}- [net] rds: fix rds-ping inducing kernel panic (Jay Fenlason) [822757 803936] {CVE-2012-2372}- [net] sock: validate data_len before allocating skb in sock_alloc_send_pskb() (Jason Wang) [816292 814504] {CVE-2012-2136}- [virt] kvm: Fix buffer overflow in kvm_set_irq() (Avi Kivity) [816154 816155] {CVE-2012-2137}- [drm] integer overflow in drm_mode_dirtyfb_ioctl() (Dave Airlie) [773249 773250] {CVE-2012-0044}- [net] netfilter: Fix ip_route_me_harder triggering ip_rt_bug (Jiri Benc) [824429 812108]- [net] netfilter/tproxy: do not assign timewait sockets to skb->sk (Jiri Benc) [824429 812108]- [virt] xenpv: avoid paravirt __pmd in read_pmd_atomic (Andrew Jones) [823903 822697]- [infiniband] mlx4: fix RoCE oops (Doug Ledford) [799946 749059]- [mm] read_pmd_atomic: fix pmd_populate SMP race condition (Andrea Arcangeli) [822824 820762] {CVE-2012-2373}- [infiniband] mlx4: check return code and bail on error (Doug Ledford) [799946 749059]- [infiniband] mlx4: use locking when walking netdev list (Doug Ledford) [799946 749059]- [mm] thp: fix pmd_bad() triggering in code paths holding mmap_sem read mode (Andrea Arcangeli) [803808 800328] {CVE-2012-1179}[2.6.32-220.20.1.el6]- [vhost] net: fix possible NULL pointer dereference of vq->bufs (Jason Wang) [814286 814288] {CVE-2012-2119}- [net] macvtap: validate zerocopy vectors before building skb (Jason Wang) [814286 814288] {CVE-2012-2119}- [net] macvtap: set SKBTX_DEV_ZEROCOPY only when skb is built successfully (Jason Wang) [814286 814288] {CVE-2012-2119}- [net] macvtap: put zerocopy page when fail to get all requested user pages (Jason Wang) [814286 814288] {CVE-2012-2119}- [net] macvtap: fix zerocopy offset calculation when building skb (Jason Wang) [814286 814288] {CVE-2012-2119}- [net] bonding: remove entries for master_ip and vlan_ip and query devices instead (Andy Gospodarek) [816197 810299]- [virt] KVM: lock slots_lock around device assignment (Alex Williamson) [814154 811653] {CVE-2012-2121}- [virt] kvm: unmap pages from the iommu when slots are removed (Alex Williamson) [814154 811653] {CVE-2012-2121}- [virt] xenfv: fix hangs when kdumping (Andrew Jones) [812953 811815]- [s390x] zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl (Hendrik Brueckner) [810125 808487]- [drm] i915: suspend fbdev device around suspend/hibernate (Dave Airlie) [818503 746169]- [fs] tmpfs: fix off-by-one in max_blocks checks (Eric Sandeen) [809399 783497]- [net] bonding: Allow Bonding driver to disable/enable LRO on slaves (Neil Horman) [818504 772317]- [virt] xen-blkfront: conditionally drop name and minor adjustments for emulated scsi devs (Laszlo Ersek) [818505 729586]- [virt] xen-blk: plug device number leak on error path in xlblk_init (Laszlo Ersek) [818505 729586][2.6.32-220.19.1.el6]- [pci] Fix unbootable HP DL385G6 on 2.6.32-220 by properly disabling pcie aspm (Dave Wysochanski) [819614 769626][2.6.32-220.18.1.el6]- [netdrv] iwlwifi: add option to disable 5Ghz band (Stanislaw Gruszka) [816226 812259]- [netdrv] iwlwifi: cancel scan before nulify ctx->vif (Stanislaw Gruszka) [816225 801730]- [netdrv] iwlwifi: do not nulify ctx->vif on reset (Stanislaw Gruszka) [816225 801730]- [net] mac80211: workaround crash at ieee80211_mgd_probe_ap_send (Stanislaw Gruszka) [814657 808095]- [net] bonding: 802.3ad - fix agg_device_up (Veaceslav Falico) [817466 806081]- [scsi] st: fix memory leak with 1MB tape I/O (David Milburn) [816271 811703]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0743");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0743.html");
script_cve_id("CVE-2012-2121","CVE-2012-2136","CVE-2012-0044","CVE-2012-1179","CVE-2012-2119","CVE-2012-2123","CVE-2012-2137","CVE-2012-2372","CVE-2012-2373");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.23.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

