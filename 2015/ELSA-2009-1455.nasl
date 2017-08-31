# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1455.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122433");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:45:17 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1455");
script_tag(name: "insight", value: "ELSA-2009-1455 -  kernel security and bug fix update - [2.6.18-164.2.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb ( John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314][2.6.18-164.2.1.el5]- [x86_64] kvm: bound last_kvm to prevent backwards time (Glauber Costa ) [524527 524076]- [x86] kvm: fix vsyscall going backwards (Glauber Costa ) [524527 524076]- [misc] fix RNG to not use first generated random block (Neil Horman ) [523289 522860]- [x86] kvm: mark kvmclock_init as cpuinit (Glauber Costa ) [524151 523450]- [x86_64] kvm: allow kvmclock to be overwritten (Glauber Costa ) [524150 523447]- [x86] kvmclock: fix bogus wallclock value (Glauber Costa ) [524152 519771]- [scsi] scsi_dh_rdace: add more sun hardware (mchristi@redhat.com ) [523237 518496]- [misc] cprng: fix cont test to be fips compliant (Neil Horman ) [523290 523259]- [net] bridge: fix LRO crash with tun (Andy Gospodarek ) [522636 483646]- Revert: [x86_64] fix gettimeoday TSC overflow issue - 1 (Don Zickus ) [489847 467942]- Revert: [net] atalk/irda: memory leak to user in getname (Danny Feng ) [519309 519310] {CVE-2009-3001 CVE-2009-3002}[2.6.18-164.1.1.el5]- [net] sky2: revert some phy power refactoring changes (Neil Horman ) [517976 509891]- [net] atalk/irda: memory leak to user in getname (Danny Feng ) [519309 519310] {CVE-2009-3001 CVE-2009-3002}- [x86_64] fix gettimeoday TSC overflow issue - 1 (Prarit Bhargava ) [489847 467942]- [md] prevent crash when accessing suspend_* sysfs attr (Danny Feng ) [518135 518136] {CVE-2009-2849}- [nfs] nlm_lookup_host: don't return invalidated nlm_host (Sachin S. Prabhu ) [517967 507549]- [net] bonding: tlb/alb: set active slave when enslaving (Jiri Pirko ) [517971 499884]- [nfs] r/w I/O perf degraded by FLUSH_STABLE page flush (Peter Staubach ) [521244 498433]- [SELinux] allow preemption b/w transition perm checks (Eric Paris ) [520919 516216]- [scsi] scsi_transport_fc: fc_user_scan correction (David Milburn ) [521239 515176]- [net] tg3: refrain from touching MPS (John Feeney ) [521241 516123]- [net] qlge: fix hangs and read performance (Marcus Barrow ) [519783 517893]- [scsi] qla2xxx: allow use of MSI when MSI-X disabled (Marcus Barrow ) [519782 517922]- [net] mlx4_en fix for vlan traffic (Doug Ledford ) [520906 514141]- [net] mlx4_core: fails to load on large systems (Doug Ledford ) [520908 514147]- [x86] disable kvmclock by default (Glauber Costa ) [520685 476075]- [x86] disable kvmclock when shuting the machine down (Glauber Costa ) [520685 476075]- [x86] re-register clock area in prepare_boot_cpu (Glauber Costa ) [520685 476075]- [x86] kvmclock smp support (Glauber Costa ) [520685 476075]- [x86] use kvm wallclock (Glauber Costa ) [520685 476075]- [x86_64] kvm clocksource's implementation (Glauber Costa ) [520685 476075]- [x86] kvm: import kvmclock.c (Glauber Costa ) [520685 476075]- [x86] kvm: import pvclock.c and headers (Glauber Costa ) [520685 476075]- [x86] export additional cpu flags in /proc/cpuinfo (Prarit Bhargava ) [520686 517928]- [x86] detect APIC clock calibration problems (Prarit Bhargava ) [521238 503957]- [x86] pnpacpi: fix serial ports on IBM Point-of-Sale HW (Kevin Monroe ) [520905 506799]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1455");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1455.html");
script_cve_id("CVE-2009-2849");
script_tag(name:"cvss_base", value:"4.7");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.2.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.2.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.2.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.2.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.2.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.2.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.2.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.2.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

