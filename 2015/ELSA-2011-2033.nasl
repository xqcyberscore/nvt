# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-2033.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122051");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:12:15 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-2033");
script_tag(name: "insight", value: "ELSA-2011-2033 -  Unbreakable Enterprise kernel security update - [2.6.32-200.23.1.el6uek]- net: Remove atmclip.h to prevent break kabi check.- KConfig: add CONFIG_UEK5=n to ol6/config-generic[2.6.32-200.22.1.el6uek]- ipv6: make fragment identifications less predictable (Joe Jin) {CVE-2011-2699}- vlan: fix panic when handling priority tagged frames (Joe Jin) {CVE-2011-3593}- ipv6: udp: fix the wrong headroom check (Maxim Uvarov) {CVE-2011-4326}- b43: allocate receive buffers big enough for max frame len + offset (Maxim Uvarov) {CVE-2011-3359}- fuse: check size of FUSE_NOTIFY_INVAL_ENTRY message (Maxim Uvarov) {CVE-2011-3353}- cifs: fix possible memory corruption in CIFSFindNext (Maxim Uvarov) {CVE-2011-3191}- crypto: md5 - Add export support (Maxim Uvarov) {CVE-2011-2699}- fs/partitions/efi.c: corrupted GUID partition tables can cause kernel oops (Maxim Uvarov) {CVE-2011-1577}- block: use struct parsed_partitions *state universally in partition check code (Maxim Uvarov)- net: Compute protocol sequence numbers and fragment IDs using MD5. (Maxim Uvarov) {CVE-2011-3188}- crypto: Move md5_transform to lib/md5.c (Maxim Uvarov) {CVE-2011-3188}- perf tools: do not look at ./config for configuration (Maxim Uvarov) {CVE-2011-2905}- Make TASKSTATS require root access (Maxim Uvarov) {CVE-2011-2494}- TPM: Zero buffer after copying to userspace (Maxim Uvarov) {CVE-2011-1162}- TPM: Call tpm_transmit with correct size (Maxim Uvarov){CVE-2011-1161}- fnic: fix panic while booting in fnic(Xiaowei Hu)- Revert 'PCI hotplug: acpiphp: set current_state to D0 in register_slot' (Guru Anbalagane)- xen: drop xen_sched_clock in favour of using plain wallclock time (Jeremy Fitzhardinge)[2.6.32-200.21.1.el6uek]- PCI: Set device power state to PCI_D0 for device without native PM support (Ajaykumar Hotchandani) [orabug 13033435]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-2033");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-2033.html");
script_cve_id("CVE-2011-1162","CVE-2011-1577","CVE-2011-2494","CVE-2011-2699","CVE-2011-3188","CVE-2011-3191","CVE-2011-3353","CVE-2011-3593","CVE-2011-4326");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~200.23.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~200.23.1.el5uek~1.5.1~4.0.53", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~200.23.1.el5uekdebug~1.5.1~4.0.53", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~200.23.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~200.23.1.el6uek~1.5.1~4.0.47", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~200.23.1.el6uekdebug~1.5.1~4.0.47", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

