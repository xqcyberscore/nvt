# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0147.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122384");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:57 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0147");
script_tag(name: "insight", value: "ELSA-2010-0147 -  kernel security and bug fix update - [2.6.18-164.15.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb ( John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]- FP register state is corrupted during the handling a SIGSEGV (Chuck Anderson) [orabug 7708133]- [x86_64] PCI space below 4GB forces mem remap above 1TB (Larry Woodman) [523522]- [cpufreq] P-state limit: limit can never be increased (Stanislaw Gruszka) [489566]- [rds] patch rds to 4.0-ora-1.4.2-10 (Andy Grover, Tina Yang) [orabug 9168046] [RHBZ 546374][2.6.18-164.15.1.el5]- [net] sctp: backport cleanups for ootb handling V2 (Neil Horman) [555666 555667] {CVE-2010-0008}- Reverting: [net] sctp: backport cleanups for ootb handling (Neil Horman) [555666 555667] {CVE-2010-0008}[2.6.18-164.14.1.el5]- [fs] ext4: Avoid null pointer dereference when decoding EROFS w/o a journal (Jiri Pirko) [547256 547257] {CVE-2009-4308}- [net] sctp: backport cleanups for ootb handling (Neil Horman) [555666 555667] {CVE-2010-0008}- [mm] fix sys_move_pages infoleak (Eugene Teo) [562589 562590] {CVE-2010-0415}- [x86_64] wire up compat sched_rr_get_interval (Danny Feng) [557684 557092]- [net] netfilter: enforce CAP_NET_ADMIN in ebtables (Danny Feng) [555242 555243] {CVE-2010-0007}- [misc] fix kernel info leak with print-fatal-signals=1 (Danny Feng) [554583 554584] {CVE-2010-0003}- [net] ipv6: fix OOPS in ip6_dst_lookup_tail (Thomas Graf) [559238 552354]- [kvm] pvclock on i386 suffers from double registering (Glauber Costa) [561454 557095]- [pci] VF can't be enabled in dom0 (Don Dutile) [560665 547980]- [kvm] kvmclock won't restore properly after resume (Glauber Costa) [560640 539521]- [mm] prevent performance hit for 32-bit apps on x86_64 (Larry Woodman) [562746 544448]- [fs] fix possible inode corruption on unlock (Eric Sandeen) [564281 545612]- [gfs2] careful unlinking inodes (Steven Whitehouse ) [564288 519049]- [gfs2] gfs2_delete_inode failing on RO filesystem (Abhijith Das ) [564290 501359][2.6.18-164.13.1.el5]- [net] e1000e: fix broken wol (Andy Gospodarek) [559335 557974]- [net] gro: fix illegal merging of trailer trash (Herbert Xu) [561417 537876]- [xen] hook sched rebalance logic to opt_hardvirt (Christopher Lalancette ) [562777 529271]- [xen] crank the correct stat in the scheduler (Christopher Lalancette ) [562777 529271]- [xen] whitespace fixups in xen scheduler (Christopher Lalancette ) [562777 529271]- [scsi] cciss: ignore stale commands after reboot (Tomas Henzl ) [562772 525440]- [scsi] cciss: version change (Tomas Henzl ) [562772 525440]- [scsi] cciss: switch to using hlist (Tomas Henzl ) [562772 525440]- [net] bonding: allow bond in mode balance-alb to work (Jiri Pirko ) [560588 487763]- [net] e1000e: fix WoL on 82577/82578 (Jiri Pirko ) [543449 517593][2.6.18-164.12.1.el5]- [net] e1000: fix rx length check errors (Neil Horman) [552137 552138] {CVE-2009-4536}- Revert: [net] e1000, r9169: fix rx length check errors (Cong Wang ) [550914 550915]- [fs] jbd: fix race in slab creation/deletion (Josef Bacik) [553132 496847]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0147");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0147.html");
script_cve_id("CVE-2009-4308","CVE-2010-0003","CVE-2010-0007","CVE-2010-0008","CVE-2010-0415","CVE-2010-0437");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.15.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.15.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.15.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.15.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.15.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.15.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.15.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.15.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

