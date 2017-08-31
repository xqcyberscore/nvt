# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0744.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123637");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:36 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0744");
script_tag(name: "insight", value: "ELSA-2013-0744 -  kernel security and bug fix update - [2.6.32-358.6.1]- [virt] kvm: accept unaligned MSR_KVM_SYSTEM_TIME writes (Petr Matousek) [917020 917021] {CVE-2013-1796}- [char] tty: hold lock across tty buffer finding and buffer filling (Prarit Bhargava) [928686 901780]- [net] tcp: fix for zero packets_in_flight was too broad (Thomas Graf) [927309 920794]- [net] tcp: frto should not set snd_cwnd to 0 (Thomas Graf) [927309 920794]- [net] tcp: fix an infinite loop in tcp_slow_start() (Thomas Graf) [927309 920794]- [net] tcp: fix ABC in tcp_slow_start() (Thomas Graf) [927309 920794]- [netdrv] ehea: avoid accessing a NULL vgrp (Steve Best) [921535 911359]- [net] sunrpc: Get rid of the redundant xprt->shutdown bit field (J. Bruce Fields) [915579 893584]- [virt] kvm: do not #GP on unaligned MSR_KVM_SYSTEM_TIME write (Gleb Natapov) [917020 917021] {CVE-2013-1796}- [drm] i915: bounds check execbuffer relocation count (Nikola Pajkovsky) [920523 920525] {CVE-2013-0913}- [x86] irq: add quirk for broken interrupt remapping on 55XX chipsets (Neil Horman) [911267 887006]- [kvm] Convert MSR_KVM_SYSTEM_TIME to use gfn_to_hva_cache functions (Gleb Natapov) [917024 917025] {CVE-2013-1797}- [kvm] Fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (Gleb Natapov) [917020 917021] {CVE-2013-1796}- [kvm] Fix bounds checking in ioapic indirect register reads (Gleb Natapov) [917030 917032] {CVE-2013-1798}- [kvm] x86: release kvmclock page on reset (Gleb Natapov) [917024 917025] {CVE-2013-1797}- [security] keys: Fix race with concurrent install_user_keyrings() (David Howells) [916681 913258] {CVE-2013-1792}- [virt] hv_balloon: Make adjustments to the pressure report (Jason Wang) [909156 902232][2.6.32-358.5.1]- [fs] xfs: use maximum schedule timeout when ail is empty (Brian Foster) [921958 883905]- [net] xfrm_user: fix info leak in copy_to_user_tmpl() (Thomas Graf) [922428 922429] {CVE-2012-6537}- [net] xfrm_user: fix info leak in copy_to_user_policy() (Thomas Graf) [922428 922429] {CVE-2012-6537}- [net] xfrm_user: fix info leak in copy_to_user_state() (Thomas Graf) [922428 922429] {CVE-2012-6537}- [net] xfrm_user: fix info leak in copy_to_user_auth() (Thomas Graf) [922428 922429] {CVE-2012-6537}- [net] atm: fix info leak in getsockopt(SO_ATMPVC) (Thomas Graf) [922386 922387] {CVE-2012-6546}- [net] atm: fix info leak via getsockname() (Thomas Graf) [922386 922387] {CVE-2012-6546}- [fs] nls: improve UTF8 -> UTF16 string conversion routine (Nikola Pajkovsky) [916118 916119] {CVE-2013-1773}- [fs] fat: Fix stat->f_namelen (Nikola Pajkovsky) [916118 916119] {CVE-2013-1773}- [netdrv] tun: fix ioctl() based info leaks (Thomas Graf) [922350 922351] {CVE-2012-6547}- [virt] x86: Add a check to catch Xen emulation of Hyper-V (Andrew Jones) [923204 918239]- [fs] cifs: fix expand_dfs_referral (Sachin Prabhu) [923098 902492]- [fs] cifs: factor smb_vol allocation out of cifs_setup_volume_info (Sachin Prabhu) [923098 902492]- [fs] cifs: have cifs_cleanup_volume_info not take a double pointer (Sachin Prabhu) [923098 902492]- [fs] nfs: Dont allow NFS silly-renamed files to be deleted, no signal (Dave Wysochanski) [920266 905095][2.6.32-358.4.1]- [fs] NLM: Ensure that we resend all pending blocking locks after a reclaim (Steve Dickson) [921150 913704]- [fs] xfs: remove log force from xfs_buf_cond_lock() (Brian Foster) [921961 896224]- [fs] xfs: recheck buffer pinned status after push trylock failure (Brian Foster) [921961 896224]- [fs] nfs: Ensure that we check lock exclusive/shared type against open modes (Dave Wysochanski) [920268 916324]- [powerpc] pseries: Fix partition migration hang in stop_topology_update (Steve Best) [921963 910597]- [infiniband] qib: correction for faulty sparse warning correction (Jay Fenlason) [922154 901701]- [usb] io_ti: Fix NULL dereference in chase_port() (Nikola Pajkovsky) [916198 916200] {CVE-2013-1774}- [net] bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Nikola Pajkovsky) [914690 914691] {CVE-2013-0349}- [char] tty: set_termios/set_termiox should not return -EINTR (Oleg Nesterov) [921145 904907]- [netdrv] ehea: fix VLAN support (Steve Best) [921535 911359]- [net] xfrm_user: return error pointer instead of NULL (Thomas Graf) [919388 919389] {CVE-2013-1826}- [net] dccp: check ccid before NULL poiter dereference (Weiping Pan) [919187 919188] {CVE-2013-1827}- [mm] tmpfs: fix use-after-free of mempolicy object (Nikola Pajkovsky) [915714 915715] {CVE-2013-1767}- [fs] fuse: set page_descs length in fuse_buffered_write() (Brian Foster) [916957 915135]- [fs] vfs: fix pointer dereference validation in d_validate (Carlos Maiolino) [915583 876600]- [fs] cifs: after upcalling for krb5 creds, invalidate key rather than revoking it (Niels de Vos) [912452 885899]- [fs] cifs: tmp_key_invalidate() should not set key->expiry to 0 (Niels de Vos) [912452 885899]- [block] disable discard request merge temporarily (Mike Snitzer) [911475 907844][2.6.32-358.3.1]- [net] netfilter: improve out-of-sync situation in TCP tracking (Flavio Leitner) [917690 629857]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0744");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0744.html");
script_cve_id("CVE-2013-1796","CVE-2013-1797","CVE-2013-1798","CVE-2013-0913","CVE-2013-1773","CVE-2012-6537","CVE-2012-6546","CVE-2012-6547","CVE-2013-1826","CVE-2013-0349","CVE-2013-1767","CVE-2013-1774","CVE-2013-1792","CVE-2013-1827");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.6.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

