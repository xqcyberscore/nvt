# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1479.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122050");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:12:14 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1479");
script_tag(name: "insight", value: "ELSA-2011-1479 -  kernel security, bug fix, and enhancement update - kernel[2.6.18-274.12.1.0.1.el5]- fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan)- [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan)- [scsi] add additional scsi medium error handling (John Sobecki) [orabug 12904887]- [x86] Fix lvt0 reset when hvm boot up with noapic param- [scsi] remove printk's when doing I/O to a dead device (John Sobecki, Chris Mason) [orabug 12342275]- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]- bonding: reread information about speed and duplex when interface goes up (John Haxby) [orabug 11890822]- [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646]- [scsi] fix scsi hotplug and rescan race [orabug 10260172]- fix filp_close() race (Joe Jin) [orabug 10335998]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- [aio] patch removes limit on number of retries (Srinivas Eeda) [orabug 10044782]- [loop] Do not call loop_unplug for not configured loop device (orabug 10314497)[2.6.18-274.12.1.el5]- Revert: [virt] kvm: fix lost tick accounting for 32 bit kvm-clock (Rik van Riel) [747875 731599][2.6.18-274.11.1.el5]- [fs] gfs2: speed up large file delete/unlink (Robert S Peterson) [743806 738440]- [fs] cifs: fix wrong buffer length returned by SendReceive (Sachin Prabhu) [750842 720363]- [virt] kvm: fix lost tick accounting for 32 bit kvm-clock (Rik van Riel) [747875 731599]- [virt] xen/netback: disable features not supported by netfront (Paolo Bonzini) [746600 746225]- [fs] nfs: don't redirty inodes with no outstanding commits (Jeff Layton) [750477 739665]- [net] tg3: call netif_carrier_off to initialize operstate value (John Feeney) [744700 635982]- [xen] make test_assign_device domctl dependent on intremap hw (Laszlo Ersek) [745726 740203]- [xen] Propagate target dom within XEN_DOMCTL_test_assign_device (Laszlo Ersek) [745726 740203]- [net] sctp: encode PROTOCOL VIOLATION error cause correctly (Thomas Graf) [750457 636828]- [fs] cifs: always do is_path_accessible check in cifs_mount (Jeff Layton) [738299 738300] {CVE-2011-3363}- [fs] cifs: add fallback in is_path_accessible for old servers (Jeff Layton) [738299 738300] {CVE-2011-3363}- [char] tpm: Zero buffer after copying to userspace (Jiri Benc) [732630 732631] {CVE-2011-1162}- [fs] hfs: fix hfs_find_init() sb->ext_tree NULL ptr oops (Phillip Lougher) [712775 712776] {CVE-2011-2203}- [net] sctp: Set correct error cause value for missing parameters (Thomas Graf) [750451 629938]- [misc] kernel: plug taskstats io infoleak (Jerome Marchand) [716845 716846] {CVE-2011-2494}- [usb] Make device reset stop retrying after disconnect (Don Zickus) [750841 709699]- [net] ipv6: properly use ICMP6MSGOUT_INC_STATS in ndisc_send_skb (Jiri Pirko) [743611 698728]- [scsi] Reduce error recovery time by reducing use of TURs (Mike Christie) [741273 694625]- [mm] s390: fix first time swap use results in heavy swapping (Hendrik Brueckner) [747876 722482]- [virt] xen: fix GFP mask handling in dma_alloc_coherent (Laszlo Ersek) [742282 730247]- [s390] kernel: fix system hang if hangcheck timer expires (Hendrik Brueckner) [747872 730313]- [usb] fix interface sysfs file-creation bug (Don Zickus) [750848 637930]- [usb] don't touch sysfs stuff when altsetting is unchanged (Don Zickus) [750848 637930]- [base] Fix potential deadlock in driver core (Don Zickus) [750848 637930]- [security] keys: Fix NULL deref in user-defined key type (David Howells) [751300 751301]- [xen] passthrough: block VT-d MSI trap injection (Paolo Bonzini) [716301 716302] {CVE-2011-1898}[2.6.18-274.10.1.el5]- [net] be2net: enable NETIF_F_LLTX and add own locking of Tx path (Ivan Vecera) [750912 731806]- [net] be2net: fix multicast filter programming (Ivan Vecera) [750912 731806]- [net] be2net: fix cmd-rx-filter not notifying MCC (Ivan Vecera) [750912 731806]- [net] be2net: use RX_FILTER cmd to program multicast addresses (Ivan Vecera) [750912 731806][2.6.18-274.9.1.el5]- [fs] nfs: re-add call to filemap_fdatawrite (David Jeffery) [750508 748999][2.6.18-274.8.1.el5]- [fs] nfs: Don't call iput holding nfs_access_cache_shrinker lock (Steve Dickson) [749459 585935]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1479");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1479.html");
script_cve_id("CVE-2011-1162","CVE-2011-1898","CVE-2011-2203","CVE-2011-2494","CVE-2011-3363","CVE-2011-4110");
script_tag(name:"cvss_base", value:"7.4");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.12.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.12.1.0.1.el5~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.12.1.0.1.el5PAE~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.12.1.0.1.el5debug~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.12.1.0.1.el5xen~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.12.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.12.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.12.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.12.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

