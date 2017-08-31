# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0420.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123423");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:03:36 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0420");
script_tag(name: "insight", value: "ELSA-2014-0420 -  qemu-kvm security update - [0.12.1.2-2.415.el6_5.8]- kvm-virtio-net-fix-guest-triggerable-buffer-overrun.patch [bz#1078605 bz#1078849]- kvm-qcow2-Check-backing_file_offset-CVE-2014-0144.patch [bz#1079452 bz#1079453]- kvm-qcow2-Check-refcount-table-size-CVE-2014-0144.patch [bz#1079452 bz#1079453]- kvm-qcow2-Validate-refcount-table-offset.patch [bz#1079518 bz#1086678]- kvm-qcow2-Validate-snapshot-table-offset-size-CVE-2014-0.patch [bz#1079452 bz#1079453]- kvm-qcow2-Validate-active-L1-table-offset-and-size-CVE-2.patch [bz#1079452 bz#1079453]- kvm-qcow2-Fix-backing-file-name-length-check.patch [bz#1079518 bz#1086678]- kvm-qcow2-Don-t-rely-on-free_cluster_index-in-alloc_refc.patch [bz#1079337 bz#1079338]- kvm-qcow2-Avoid-integer-overflow-in-get_refcount-CVE-201.patch [bz#1079318 bz#1079319]- kvm-qcow2-Check-new-refcount-table-size-on-growth.patch [bz#1079518 bz#1086678]- kvm-qcow2-Fix-types-in-qcow2_alloc_clusters-and-alloc_cl.patch [bz#1079518 bz#1086678]- kvm-qcow2-Protect-against-some-integer-overflows-in-bdrv.patch [bz#1079518 bz#1086678]- kvm-qcow2-Catch-some-L1-table-index-overflows.patch [bz#1079518 bz#1086678]- kvm-qcow2-Fix-new-L1-table-size-check-CVE-2014-0143.patch [bz#1079318 bz#1079319]- kvm-qcow2-Fix-NULL-dereference-in-qcow2_open-error-path-.patch [bz#1079330 bz#1079331]- kvm-qcow2-Limit-snapshot-table-size.patch [bz#1079518 bz#1086678]- kvm-block-cloop-validate-block_size-header-field-CVE-201.patch [bz#1079452 bz#1079453]- kvm-block-cloop-prevent-offsets_size-integer-overflow-CV.patch [bz#1079318 bz#1079319]- kvm-block-cloop-refuse-images-with-huge-offsets-arrays-C.patch [bz#1079452 bz#1079453]- kvm-block-cloop-Fix-coding-style.patch [bz#1079518 bz#1086678]- kvm-cloop-Fix-bdrv_open-error-handling.patch [bz#1079518 bz#1086678]- kvm-block-cloop-refuse-images-with-bogus-offsets-CVE-201.patch [bz#1079452 bz#1079453]- kvm-block-cloop-Use-g_free-instead-of-free.patch [bz#1079518 bz#1086678]- kvm-block-cloop-fix-offsets-size-off-by-one.patch [bz#1079518 bz#1086678]- kvm-bochs-Fix-bdrv_open-error-handling.patch [bz#1079518 bz#1086678]- kvm-bochs-Unify-header-structs-and-make-them-QEMU_PACKED.patch [bz#1079518 bz#1086678]- kvm-bochs-Use-unsigned-variables-for-offsets-and-sizes-C.patch [bz#1079337 bz#1079338]- kvm-bochs-Check-catalog_size-header-field-CVE-2014-0143.patch [bz#1079318 bz#1079319]- kvm-bochs-Check-extent_size-header-field-CVE-2014-0142.patch [bz#1079313 bz#1079314]- kvm-bochs-Fix-bitmap-offset-calculation.patch [bz#1079518 bz#1086678]- kvm-vpc-vhd-add-bounds-check-for-max_table_entries-and-b.patch [bz#1079452 bz#1079453]- kvm-vpc-Validate-block-size-CVE-2014-0142.patch [bz#1079313 bz#1079314]- kvm-vdi-add-bounds-checks-for-blocks_in_image-and-disk_s.patch [bz#1079452 bz#1079453]- kvm-vhdx-Bounds-checking-for-block_size-and-logical_sect.patch [bz#1079343 bz#1079344]- kvm-curl-check-data-size-before-memcpy-to-local-buffer.-.patch [bz#1079452 bz#1079453]- kvm-dmg-Fix-bdrv_open-error-handling.patch [bz#1079518 bz#1086678]- kvm-dmg-coding-style-and-indentation-cleanup.patch [bz#1079518 bz#1086678]- kvm-dmg-prevent-out-of-bounds-array-access-on-terminator.patch [bz#1079518 bz#1086678]- kvm-dmg-drop-broken-bdrv_pread-loop.patch [bz#1079518 bz#1086678]- kvm-dmg-use-appropriate-types-when-reading-chunks.patch [bz#1079518 bz#1086678]- kvm-dmg-sanitize-chunk-length-and-sectorcount-CVE-2014-0.patch [bz#1079323 bz#1079324]- kvm-dmg-use-uint64_t-consistently-for-sectors-and-length.patch [bz#1079518 bz#1086678]- kvm-dmg-prevent-chunk-buffer-overflow-CVE-2014-0145.patch [bz#1079323 bz#1079324]- kvm-block-Limit-request-size-CVE-2014-0143.patch [bz#1079318 bz#1079319]- kvm-parallels-Fix-catalog-size-integer-overflow-CVE-2014.patch [bz#1079318 bz#1079319]- kvm-parallels-Sanity-check-for-s-tracks-CVE-2014-0142.patch [bz#1079313 bz#1079314]- kvm-bochs-Fix-memory-leak-in-bochs_open-error-path.patch [bz#1079518 bz#1086678]- kvm-bochs-Fix-catalog-size-check.patch [bz#1079518 bz#1086678]- Resolves: bz#1078849 (EMBARGOED CVE-2014-0150 qemu-kvm: qemu: virtio-net: buffer overflow in virtio_net_handle_mac() function [rhel-6.5.z])- Resolves: bz#1079313 (CVE-2014-0142 qemu-kvm: qemu: crash by possible division by zero [rhel-6.5.z])- Resolves: bz#1079318 (CVE-2014-0143 qemu-kvm: Qemu: block: multiple integer overflow flaws [rhel-6.5.z])- Resolves: bz#1079323 (CVE-2014-0145 qemu-kvm: Qemu: prevent possible buffer overflows [rhel-6.5.z])- Resolves: bz#1079330 (CVE-2014-0146 qemu-kvm: Qemu: qcow2: NULL dereference in qcow2_open() error path [rhel-6.5.z])- Resolves: bz#1079337 (CVE-2014-0147 qemu-kvm: Qemu: block: possible crash due signed types or logic error [rhel-6.5.z])- Resolves: bz#1079343 (CVE-2014-0148 qemu-kvm: Qemu: vhdx: bounds checking for block_size and logical_sector_size [rhel-6.5.z])- Resolves: bz#1079452 (CVE-2014-0144 qemu-kvm: Qemu: block: missing input validation [rhel-6.5.z])- Resolves: bz#1086678 (qemu-kvm: include leftover patches from block layer security audit)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0420");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0420.html");
script_cve_id("CVE-2014-0142","CVE-2014-0143","CVE-2014-0144","CVE-2014-0145","CVE-2014-0146","CVE-2014-0147","CVE-2014-0148","CVE-2014-0150");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

