# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-2523.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123629");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:29 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-2523");
script_tag(name: "insight", value: "ELSA-2013-2523 - Unbreakable Enterprise kernel security and bugfix update - [2.6.39-400.23.1]- Parallel mtrr init between cpus (Zhenzhong Duan) [Orabug: 16777774]- Merge tag 'v2.6.39-400.21.1.16748891' of git://ca-git.us.oracle.com/linux-uek-2.6.39-ofed into uek-2.6.39-400 (Maxim Uvarov) [Orabug: 16748891]- xen-blkfront: use a different scatterlist for each request (Roger Pau Monne)- Fix EN driver to work with newer FWs based on latest mlx4_core (Yuval Shaia) [Orabug: 16748891][2.6.39-400.22.1]- block: default SCSI command filter does not accomodate commands overlap across device classes (Jamie Iles) [Orabug: 16387137] {CVE-2012-4542}- Merge tag 'v2.6.39-400.21.1#bug16684527' of git://ca-git.us.oracle.com/linux-joejin-public into uek-2.6.39-400_errata (Maxim Uvarov) [Orabug: 16684527]- KVM: x86: Convert MSR_KVM_SYSTEM_TIME to use gfn_to_hva_cache functions (CVE-2013-1797) (Andy Honig) [Orabug: 16711660] {CVE-2013-1797}- Bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Anderson Lizardo) [Orabug: 16711065] {CVE-2013-0349}- USB: io_ti: Fix NULL dereference in chase_port() (Wolfgang Frisch) [Orabug: 16425358] {CVE-2013-1774}- keys: fix race with concurrent install_user_keyrings() (David Howells) [Orabug: 16493354] {CVE-2013-1792}- KVM: Fix bounds checking in ioapic indirect register reads (CVE-2013-1798) (Andy Honig) [Orabug: 16710951] {CVE-2013-1798}- KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (CVE-2013-1796) (Andy Honig) [Orabug: 16710806] {CVE-2013-1796}- tmpfs: fix use-after-free of mempolicy object (Greg Thelen) [Orabug: 16515833] {CVE-2013-1767}- procfs: do not confuse jiffies with cputime64_t (Andreas Schwab) [Orabug: 16673925]- procfs: do not overflow get_{idle,iowait}_time for nohz (Michal Hocko) [Orabug: 16673925]- xen/evtchn: Handle VIRQ_TIMER before any other hardirq in event loop. (Keir Fraser) [Orabug: 16093126]- Fix device removal NULL pointer dereference (Joe Jin) [Orabug: 16684527]- put stricter guards on queue dead checks (James Bottomley) [Orabug: 16684527]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-2523");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-2523.html");
script_cve_id("CVE-2012-4542");
script_tag(name:"cvss_base", value:"4.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

