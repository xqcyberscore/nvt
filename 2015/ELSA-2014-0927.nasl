# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0927.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123367");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0927");
script_tag(name: "insight", value: "ELSA-2014-0927 -  qemu-kvm security and bug fix update - [1.5.3-60.el7_0.5]- kvm-Allow-mismatched-virtio-config-len.patch [bz#1095782]- Resolves: bz#1095782 (CVE-2014-0182 qemu-kvm: qemu: virtio: out-of-bounds buffer write on state load with invalid config_len [rhel-7.0.z])[1.5.3-60.el7_0.4]- kvm-zero-initialize-KVM_SET_GSI_ROUTING-input.patch [bz#1110693]- kvm-skip-system-call-when-msi-route-is-unchanged.patch [bz#1110693]- Resolves: bz#1110693 (2x RHEL 5.10 VM running on RHEL 7 KVM have low TCP_STREAM throughput)[1.5.3-60.el7_0.3]- kvm-virtio-net-fix-buffer-overflow-on-invalid-state-load.patch [bz#1095677]- kvm-virtio-net-out-of-bounds-buffer-write-on-load.patch [bz#1095684]- kvm-virtio-net-out-of-bounds-buffer-write-on-invalid-sta.patch [bz#1095689]- kvm-virtio-out-of-bounds-buffer-write-on-invalid-state-l.patch [bz#1095694]- kvm-virtio-avoid-buffer-overrun-on-incoming-migration.patch [bz#1095737]- kvm-virtio-scsi-fix-buffer-overrun-on-invalid-state-load.patch [bz#1095741]- kvm-virtio-validate-config_len-on-load.patch [bz#1095782]- kvm-virtio-validate-num_sg-when-mapping.patch [bz#1095765]- kvm-virtio-allow-mapping-up-to-max-queue-size.patch [bz#1095765]- kvm-vmstate-add-VMS_MUST_EXIST.patch [bz#1095706]- kvm-vmstate-add-VMSTATE_VALIDATE.patch [bz#1095706]- kvm-hpet-fix-buffer-overrun-on-invalid-state-load.patch [bz#1095706]- kvm-hw-pci-pcie_aer.c-fix-buffer-overruns-on-invalid-sta.patch [bz#1095714]- kvm-usb-sanity-check-setup_index-setup_len-in-post_load.patch [bz#1095746]- kvm-usb-sanity-check-setup_index-setup_len-in-post_l2.patch [bz#1095746]- kvm-usb-fix-up-post-load-checks.patch [bz#1096828]- kvm-XBZRLE-Fix-qemu-crash-when-resize-the-xbzrle-cache.patch [bz#1110191]- kvm-Provide-init-function-for-ram-migration.patch [bz#1110191]- kvm-Init-the-XBZRLE.lock-in-ram_mig_init.patch [bz#1110191]- kvm-XBZRLE-Fix-one-XBZRLE-corruption-issues.patch [bz#1110191]- kvm-Count-used-RAMBlock-pages-for-migration_dirty_pages.patch [bz#1110189]- kvm-qcow-correctly-propagate-errors.patch [bz#1097229]- kvm-qcow1-Make-padding-in-the-header-explicit.patch [bz#1097229]- kvm-qcow1-Check-maximum-cluster-size.patch [bz#1097229]- kvm-qcow1-Validate-L2-table-size-CVE-2014-0222.patch [bz#1097229]- kvm-qcow1-Validate-image-size-CVE-2014-0223.patch [bz#1097236]- kvm-qcow1-Stricter-backing-file-length-check.patch [bz#1097236]- kvm-char-restore-read-callback-on-a-reattached-hotplug-c.patch [bz#1110219]- kvm-qcow2-Free-preallocated-zero-clusters.patch [bz#1110188]- kvm-qemu-iotests-Discard-preallocated-zero-clusters.patch [bz#1110188]- Resolves: bz#1095677 (CVE-2013-4148 qemu-kvm: qemu: virtio-net: buffer overflow on invalid state load [rhel-7.0.z])- Resolves: bz#1095684 (CVE-2013-4149 qemu-kvm: qemu: virtio-net: out-of-bounds buffer write on load [rhel-7.0.z])- Resolves: bz#1095689 (CVE-2013-4150 qemu-kvm: qemu: virtio-net: out-of-bounds buffer write on invalid state load [rhel-7.0.z])- Resolves: bz#1095694 (CVE-2013-4151 qemu-kvm: qemu: virtio: out-of-bounds buffer write on invalid state load [rhel-7.0.z])- Resolves: bz#1095706 (CVE-2013-4527 qemu-kvm: qemu: hpet: buffer overrun on invalid state load [rhel-7.0.z])- Resolves: bz#1095714 (CVE-2013-4529 qemu-kvm: qemu: hw/pci/pcie_aer.c: buffer overrun on invalid state load [rhel-7.0.z])- Resolves: bz#1095737 (CVE-2013-6399 qemu-kvm: qemu: virtio: buffer overrun on incoming migration [rhel-7.0.z])- Resolves: bz#1095741 (CVE-2013-4542 qemu-kvm: qemu: virtio-scsi: buffer overrun on invalid state load [rhel-7.0.z])- Resolves: bz#1095746 (CVE-2013-4541 qemu-kvm: qemu: usb: insufficient sanity checking of setup_index+setup_len in post_load [rhel-7.0.z])- Resolves: bz#1095765 (CVE-2013-4535 CVE-2013-4536 qemu-kvm: qemu: virtio: insufficient validation of num_sg when mapping [rhel-7.0.z])- Resolves: bz#1095782 (CVE-2014-0182 qemu-kvm: qemu: virtio: out-of-bounds buffer write on state load with invalid config_len [rhel-7.0.z])- Resolves: bz#1096828 (CVE-2014-3461 qemu-kvm: Qemu: usb: fix up post load checks [rhel-7.0.z])- Resolves: bz#1097229 (CVE-2014-0222 qemu-kvm: Qemu: qcow1: validate L2 table size to avoid integer overflows [rhel-7.0.z])- Resolves: bz#1097236 (CVE-2014-0223 qemu-kvm: Qemu: qcow1: validate image size to avoid out-of-bounds memory access [rhel-7.0.z])- Resolves: bz#1110188 (qcow2 corruptions (leaked clusters after installing a rhel7 guest using virtio_scsi))- Resolves: bz#1110189 (migration can not finish with 1024k 'remaining ram' left after hotunplug 4 nics)- Resolves: bz#1110191 (Reduce the migrate cache size during migration causes qemu segment fault)- Resolves: bz#1110219 (Guest can't receive any character transmitted from host after hot unplugging virtserialport then hot plugging again)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0927");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0927.html");
script_cve_id("CVE-2013-4148","CVE-2013-4151","CVE-2013-4535","CVE-2013-4536","CVE-2013-4541","CVE-2013-4542","CVE-2013-6399","CVE-2014-0182","CVE-2014-3461","CVE-2013-4149","CVE-2013-4150","CVE-2013-4527","CVE-2013-4529","CVE-2014-0222","CVE-2014-0223");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.5", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

