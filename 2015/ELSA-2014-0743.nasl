# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0743.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123397");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:03:16 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0743");
script_tag(name: "insight", value: "ELSA-2014-0743 -  qemu-kvm security and bug fix update - [0.12.1.2-2.415.el6_5.10]- kvm-virtio-out-of-bounds-buffer-write-on-invalid-state-l.patch [bz#1095692]- kvm-usb-sanity-check-setup_index-setup_len-in-post_load.patch [bz#1095743]- kvm-usb-sanity-check-setup_index-setup_len-in-post_load-2.patch [bz#1095743]- kvm-virtio-scsi-fix-buffer-overrun-on-invalid-state-load.patch [bz#1095739]- kvm-virtio-avoid-buffer-overrun-on-incoming-migration.patch [bz#1095735]- kvm-virtio-validate-num_sg-when-mapping.patch [bz#1095763 bz#1096124]- kvm-virtio-allow-mapping-up-to-max-queue-size.patch [bz#1095763 bz#1096124]- kvm-enable-PCI-multiple-segments-for-pass-through-device.patch [bz#1099941]- kvm-virtio-net-fix-buffer-overflow-on-invalid-state-load.patch [bz#1095675]- kvm-virtio-validate-config_len-on-load.patch [bz#1095779]- kvm-usb-fix-up-post-load-checks.patch [bz#1096825]- kvm-CPU-hotplug-use-apic_id_for_cpu-round-2-RHEL-6-only.patch [bz#1100575]- Resolves: bz#1095675 ()- Resolves: bz#1095692 ()- Resolves: bz#1095735 ()- Resolves: bz#1095739 ()- Resolves: bz#1095743 ()- Resolves: bz#1095763 ()- Resolves: bz#1095779 ()- Resolves: bz#1096124 ()- Resolves: bz#1096825 ()- Resolves: bz#1099941 ()- Resolves: bz#1100575 (Some vCPU topologies not accepted by libvirt)[0.12.1.2-2.415.el6_5.9]- kvm-ide-Correct-improper-smart-self-test-counter-reset-i.patch [bz#1087978]- Resolves: bz#1087978 (CVE-2014-2894 qemu-kvm: QEMU: out of bounds buffer accesses, guest triggerable via IDE SMART [rhel-6.5.z])"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0743");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0743.html");
script_cve_id("CVE-2013-4148","CVE-2013-4151","CVE-2013-4535","CVE-2013-4536","CVE-2013-4541","CVE-2013-4542","CVE-2013-6399","CVE-2014-0182","CVE-2014-2894","CVE-2014-3461");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

