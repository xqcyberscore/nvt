# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0885.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122555");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:47:54 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0885");
script_tag(name: "insight", value: "ELSA-2008-0885 -  kernel security and bug fix update - [2.6.18-92.1.13.0.1.el5]- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]- [splice] Fix bad unlock_page() in error case (Jens Axboe) [orabug 6263574]- [NET] fix netpoll race (Tina Yang) [orabugz 5791][2.6.18-92.1.13.el5]- [md] fix crashes in iterate_rdev (Doug Ledford ) [460128 455471]- [sound] snd_seq_oss_synth_make_info info leak (Eugene Teo ) [458000 458001] {CVE-2008-3272}- [ipmi] control BMC device ordering (peterm@redhat.com ) [459071 430157]- [ia64] fix to check module_free parameter (Masami Hiramatsu ) [460639 457961]- [misc] NULL pointer dereference in kobject_get_path (Jiri Pirko ) [459776 455460]- [xen] ia64: SMP-unsafe with XENMEM_add_to_physmap on HVM (Tetsu Yamamoto ) [459780 457137]- [net] bridge: eliminate delay on carrier up (Herbert Xu ) [458783 453526]- [fs] dio: lock refcount operations (Jeff Moyer ) [459082 455750]- [misc] serial: fix break handling for i82571 over LAN (Aristeu Rozanski ) [460509 440018]- [fs] dio: use kzalloc to zero out struct dio (Jeff Moyer ) [461091 439918]- [fs] lockd: nlmsvc_lookup_host called with f_sema held (Jeff Layton ) [459083 453094]- [net] bnx2x: chip reset and port type fixes (Andy Gospodarek ) [441259 442026][2.6.18-92.1.12.el5]- [mm] tmpfs: restore missing clear_highpage (Eugene Teo ) [426082 426083]{CVE-2007-6417}- [fs] vfs: fix lookup on deleted directory (Eugene Teo ) [457865 457866]{CVE-2008-3275}- [net] ixgbe: remove device ID for unsupported device (Andy Gospodarek ) [457484 454910]- [ppc] Event Queue overflow on eHCA adapters (Brad Peters ) [458779 446713][2.6.18-92.1.11.el5]- [mm] xpmem: inhibit page swapping under heavy mem use (George Beshers ) [456946 456574]- [xen] HV: memory corruption with large number of cpus (Chris Lalancette ) [455768 449945]- [fs] missing check before setting mount propagation (Eugene Teo ) [454392 454393]- [openib] small ipoib packet can cause an oops (Doug Ledford ) [447913 445731]- [misc] fix race in switch_uid and user signal accounting (Vince Worthington ) [456235 441762 440830]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0885");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0885.html");
script_cve_id("CVE-2007-6417","CVE-2007-6716","CVE-2008-2931","CVE-2008-3272","CVE-2008-3275");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.13.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.13.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.13.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.13.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.13.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.13.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.13.0.1.el5debug~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.13.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

