# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1386.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122066");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:12:30 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1386");
script_tag(name: "insight", value: "ELSA-2011-1386 -  kernel security, bug fix, and enhancement update - kernel: [2.6.18-274.7.1.0.1.el5] - fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan) - [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan) - [scsi] add additional scsi medium error handling (John Sobecki) [orabug 12904887] - [x86] Fix lvt0 reset when hvm boot up with noapic param - [scsi] remove printk's when doing I/O to a dead device (John Sobecki, Chris Mason) [orabug 12342275] - [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346] - [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566] - bonding: reread information about speed and duplex when interface goes up (John Haxby) [orabug 11890822] - [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646] - [scsi] fix scsi hotplug and rescan race [orabug 10260172] - fix filp_close() race (Joe Jin) [orabug 10335998] - make xenkbd.abs_pointer=1 by default [orabug 67188919] - [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514] - [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433] - [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258] - [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839] - fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042] - [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to() - [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465] - [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220] - Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615] - fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033] - [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208] - [ib] fix memory corruption (Andy Grover) [orabug 9972346] - [aio] patch removes limit on number of retries (Srinivas Eeda) [orabug 10044782] - [loop] Do not call loop_unplug for not configured loop device (orabug 10314497) [2.6.18-274.7.1.el5] - Revert: [xen] passthrough: block VT-d MSI trap injection (Paolo Bonzini) [716301 716302] {CVE-2011-1898} [2.6.18-274.6.1.el5] - [net] bridge: fix use after free in __br_deliver (Amerigo Wang) [730949 703045] {CVE-2011-2942} - [misc] remove div_long_long_rem (Prarit Bhargava) [732879 732614] {CVE-2011-3209} - [net] be2net: fix crash receiving non-member VLAN packets (Ivan Vecera) [736430 730239] {CVE-2011-3347} - [net] be2net: Use NTWK_RX_FILTER command for promiscous mode (Ivan Vecera) [736430 730239] {CVE-2011-3347} - [net] be2net: non-member vlan pkts not received in promisc mode (Ivan Vecera) [736430 730239] {CVE-2011-3347} - [net] be2net: remove bogus unlikely on vlan check (Ivan Vecera) [736430 730239] {CVE-2011-3347} - [x86] nmi: make NMI_NONE default watchdog in x86_64 hvm guests (Laszlo Ersek) [739823 707966] [2.6.18-274.5.1.el5] - [fs] proc: fix compile warning in pdeaux addition (Jarod Wilson) [732775 675781] - [fs] proc: Fix procfs race vs rmmod or hot-remove (David Howells) [732775 675781] - [net] Compute protocol seq numbers and fragment IDs using MD5 (Jiri Pirko) [732662 732663] {CVE-2011-3188} - [crypto] Move md5_transform to lib/md5.c (Jiri Pirko) [732662 732663] {CVE-2011-3188} - [fs] nfs: Fix client not honoring nosharecache mount option (David Jeffery) [734772 730097] - [mm] avoid wrapping vm_pgoff in mremap and stack expansion (Jerome Marchand) [716543 716544] {CVE-2011-2496} - [mm] Fix incorrect off-by-one centisec dirty values (Larry Woodman) [733665 691087] - [net] bnx2x: fix bringup of BCM57710 (Michal Schmidt) [737475 680411] - [virt] xen/netfront: no disable s/g when renegotiating features (Paolo Bonzini) [738392 733416] - [fs] aio: fix aio+dio completion path regression w/3rd-party bits (Jeff Moyer) [734157 727504] - [virt] xen: Allow arbitrary mtu size until frontend connected (Paolo Bonzini) [738389 697021] - [misc] hypervisor: fix race in interrupt hook code (Prarit Bhargava) [730689 692966] - [net] cnic, bnx2: Check iSCSI support early in bnx2_init_one (Neil Horman) [734761 710272] - [net] igb: fix WOL on 2nd port on i350 (Stefan Assmann) [730682 718988] - [misc] irq: fix interrupt handling for kdump under high load (Stefan Assmann) [728521 720212] [2.6.18-274.4.1.el5] - [serial] ifdef for powerpc, to only add functionality to this arch (Steve Best) [732377 707051] - [serial] 8250: Fix capabilities when changing the port type (Steve Best) [732377 707051] - [serial] 8250_pci EEH support for IBM/Digi PCIe 2-port Adapter (Steve Best) [732377 707051] - [serial] 8250_pci: Add support for Digi/IBM PCIe 2-port Adapter (Steve Best) [732377 707051] - [fs] ecryptfs: Add mount option to check uid of mounting device (Eric Sandeen) [731173 731174] {CVE-2011-1833} - [scsi] qla2xxx: Re-add checks for null fcport references (Chad Dupuis) [736275 728219] - [net] ipv6: make fragment identifications less predictable (Jiri Pirko) [723430 723431] {CVE-2011-2699} - [net] ipv6: Remove unused skb argument of ipv6_select_ident (Jiri Pirko) [723430 723431] {CVE-2011-2699} - [misc] taskstats: don't allow duplicate entries in listener mode (Jerome Marchand) [715449 715450] {CVE-2011-2484} - [net] gro: Only reset frag0 when skb can be pulled (Herbert Xu) [726553 679682] {CVE-2011-2723} - [xen] passthrough: block VT-d MSI trap injection (Paolo Bonzini) [716301 716302] {CVE-2011-1898} - [xen] iommu: disable bus-mastering on hw that causes IOMMU fault (Laszlo Ersek) [730342 730343] {CVE-2011-3131} - [usb] auerswald: fix buffer overflow (Don Zickus) [722395 722396] {CVE-2009-4067} - [fs] cifs: fix possible memory corruption in CIFSFindNext (Jeff Layton) [732870 736654 732869 732471] {CVE-2011-3191} - [fs] cifs: revert special handling for matching krb5 sessions (Jeff Layton) [697395 697396] {CVE-2011-1585} - [fs] cifs: check for NULL session password (Jeff Layton) [697395 697396] {CVE-2011-1585} - [fs] cifs: fix NULL pointer dereference in cifs_find_smb_ses (Jeff Layton) [697395 697396] {CVE-2011-1585} - [fs] cifs: clean up cifs_find_smb_ses (Jeff Layton) [697395 697396] {CVE-2011-1585} - [net] be2net: account for skb allocation failures (Ivan Vecera) [733152 730108] - [net] bnx2x: downgrade Max BW error message to debug (Michal Schmidt) [732440 727614] - [net] sock: do not change prot->obj_size (Jiri Pirko) [736742 725713] - [net] be2net: Fix Tx stall issue (Ivan Vecera) [732946 722549] - [net] be2net: rx-dropped wraparound fix (Ivan Vecera) [732945 722302] - [net] be2net: fix netdev_stats_update (Ivan Vecera) [732945 722302] - [char] tpm: Fix uninitialized usage of data buffer (Stanislaw Gruszka) [684672 684673] {CVE-2011-1160} - [fs] ext4: Fix max size and logical block counting of extent file (Lukas Czerner) [722562 722563] {CVE-2011-2695} - [fs] nfs: have nfs_flush_list issue FLUSH_SYNC writes in parallel (Jeff Layton) [730686 728508] - [xen] mm: fix race with ept_entry management (Andrew Jones) [730685 729529] - [xen] hvm: support more opcodes for MMIO (Paolo Bonzini) [728518 723755] ocfs2: [1.4.9-1.el5] - Backport the discontig block group features from mainline ocfs2 into EL5.x kernels"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1386");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1386.html");
script_cve_id("CVE-2009-4067","CVE-2011-1160","CVE-2011-1585","CVE-2011-1833","CVE-2011-2484","CVE-2011-2496","CVE-2011-2695","CVE-2011-2699","CVE-2011-2723","CVE-2011-2942","CVE-2011-3131","CVE-2011-3188","CVE-2011-3191","CVE-2011-3209","CVE-2011-3347");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.7.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.7.1.0.1.el5~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.7.1.0.1.el5PAE~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.7.1.0.1.el5debug~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.7.1.0.1.el5xen~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.7.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.7.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.7.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.7.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

