# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0704.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123362");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:47 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0704");
script_tag(name: "insight", value: "ELSA-2014-0704 -  qemu-kvm security and bug fix update - [1.5.3-60.el7_0.2]- kvm-pc-add-hot_add_cpu-callback-to-all-machine-types.patch [bz#1094820]- Resolves: bz#1094820 (Hot plug CPU not working with RHEL6 machine types running on RHEL7 host.)[1.5.3-60.el7_0.1]- kvm-iscsi-fix-indentation.patch [bz#1090978]- kvm-iscsi-correctly-propagate-errors-in-iscsi_open.patch [bz#1090978]- kvm-block-iscsi-query-for-supported-VPD-pages.patch [bz#1090978]- kvm-block-iscsi-fix-segfault-if-writesame-fails.patch [bz#1090978]- kvm-iscsi-recognize-invalid-field-ASCQ-from-WRITE-SAME-c.patch [bz#1090978]- kvm-iscsi-ignore-flushes-on-scsi-generic-devices.patch [bz#1090978]- kvm-iscsi-always-query-max-WRITE-SAME-length.patch [bz#1090978]- kvm-iscsi-Don-t-set-error-if-already-set-in-iscsi_do_inq.patch [bz#1090978]- kvm-iscsi-Remember-to-set-ret-for-iscsi_open-in-error-ca.patch [bz#1090978]- kvm-qemu_loadvm_state-shadow-SeaBIOS-for-VM-incoming-fro.patch [1091322]- kvm-uhci-UNfix-irq-routing-for-RHEL-6-machtypes-RHEL-onl.patch [bz#1090981]- kvm-ide-Correct-improper-smart-self-test-counter-reset-i.patch [bz#1093612]- Resolves: bz#1091322 (fail to reboot guest after migration from RHEL6.5 host to RHEL7.0 host)- Resolves: bz#1090981 (Guest hits call trace migrate from RHEL6.5 to RHEL7.0 host with -M 6.1 & balloon & uhci device)- Resolves: bz#1090978 (qemu-kvm: iSCSI: Failure. SENSE KEY:ILLEGAL_REQUEST(5) ASCQ:INVALID_FIELD_IN_CDB(0x2400))- Resolves: bz#1093612 (CVE-2014-2894 qemu-kvm: QEMU: out of bounds buffer accesses, guest triggerable via IDE SMART [rhel-7.0.z])"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0704");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0704.html");
script_cve_id("CVE-2014-2894");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.2", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

