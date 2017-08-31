# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0015.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131174");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-01-14 07:28:47 +0200 (Thu, 14 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0015");
script_tag(name: "insight", value: "This kernel-tmb update provides an upgrade to the upstream 4.1 longterm kernel series, currently based on 4.1.15 and resolves atleast the following security issues: It was found that the Linux kernel's keyring implementation would leak memory when adding a key to a keyring via the add_key() function. A local attacker could use this flaw to exhaust all available memory on the system. (CVE-2015-1333) A flaw was found in the Linux kernel where the deletion of a file or directory could trigger an unmount and reveal data under a mount point. This flaw was inadvertently introduced with the new feature of being able to lazily unmount a mount tree when using file system user namespaces. (CVE-2015-4176) A flaw was discovered in the kernel's collect_mounts function. If the kernel audit subsystem called collect_mounts to audit an unmounted path, it could panic the system. With this flaw, an unprivileged user could call umount (MNT_DETACH) to launch a denial-of-service attack. (CVE-2015-4177) A flaw was found in the Linux kernel which is related to the user namespace lazily unmounting file systems. The fs_pin struct has two members (m_list and s_list) which are usually initialized on use in the pin_insert_group function. However, these members might go unmodified; in this case, the system panics when it attempts to destroy or free them. This flaw could be used to launch a denial-of-service attack. (CVE-2015-4178) A DoS flaw was found for a Linux kernel built for the x86 architecture which had the KVM virtualization support(CONFIG_KVM) enabled. The kernel would be vulnerable to a NULL pointer dereference flaw in Linux kernel's kvm_apic_has_events() function while doing an ioctl. An unprivileged user able to access the /dev/kvm device could use this flaw to crash the system kernel. (CVE-2015-4692) A flaw was found in the kernel's implementation of the Berkeley Packet Filter (BPF). A local attacker could craft BPF code to crash the system by creating a situation in which the JIT compiler would fail to correctly optimize the JIT image on the last pass. This would lead to the CPU executing instructions that were not part of the JIT code. (CVE-2015-4700) The virtnet_probe function in drivers/net/virtio_net.c in the Linux kernel before 4.2 attempts to support a FRAGLIST feature without proper memory allocation, which allows guest OS users to cause a denial of service (buffer overflow and memory corruption) via a crafted sequence of fragmented packets. (CVE-2015-5156) Moein Ghasemzadeh discovered that the USB WhiteHEAT serial driver contained hardcoded attributes about the USB devices. An attacker could construct a fake WhiteHEAT USB device that, when inserted, causes a denial of service (system crash) (CVE-2015-5257). A guest to host DoS issue was found affecting various hypervisors. In that, a guest can DoS the host by triggering an infinite stream of alignment check (#AC) exceptions. This causes the microcode to enter an infinite loop where the core never receives another interrupt. The host kernel panics due to this effect (CVE-2015-5307). The get_bitmap_file function in drivers/md/md.c in the Linux kernel before 4.1.6 does not initialize a certain bitmap data structure, which allows local users to obtain sensitive information from kernel memory via a GET_BITMAP_FILE ioctl call. (CVE-2015-5697) Use-after-free vulnerability in the path_openat function in fs/namei.c in the Linux kernel 3.x and 4.x before 4.0.4 allows local users to cause a denial of service or possibly have unspecified other impact via O_TMPFILE filesystem operations that leverage a duplicate cleanup operation. (CVE-2015-5706) It was discovered that an integer overflow error existed in the SCSIgeneric (sg) driver in the Linux kernel. A local attacker with writepermission to a SCSI generic device could use this to cause a denial of service (system crash) or potentially escalate their privileges. (CVE-2015-5707) The __rds_conn_create function in net/rds/connection.c in the Linux kernel through 4.2.3 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact by using a socket that was not properly bound (CVE-2015-6937). The key_gc_unused_keys function in security/keys/gc.c in the Linux kernel through 4.2.6 allows local users to cause a denial of service (OOPS) via crafted keyctl commands (CVE-2015-7872). The vivid_fb_ioctl function in drivers/media/platform/vivid/vivid-osd.c in the Linux kernel through 4.3.3 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel memory via a crafted application (CVE-2015-7884). The dgnc_mgmt_ioctl function in drivers/staging/dgnc/dgnc_mgmt.c in the Linux kernel through 4.3.3 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel memory via a crafted application (CVE-2015-7885). A guest to host DoS issue was found affecting various hypervisors. In that, a guest can DoS the host by triggering an infinite stream of debug check (#DB) exceptions. This causes the microcode to enter an infinite loop where the core never receives another interrupt. The host kernel panics due to this effect (CVE-2015-8104). Felix Wilhelm discovered a race condition in the Xen paravirtualized drivers which can cause double fetch vulnerabilities. An attacker in the paravirtualized guest could exploit this flaw to cause a denial of service (crash the host) or potentially execute arbitrary code on the host (CVE-2015-8550 / XSA-155). Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not perform sanity checks on the device's state. An attacker could exploit this flaw to cause a denial of service (NULL dereference) on the host (CVE-2015-8551 / XSA-157). Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not perform sanity checks on the device's state. An attacker could exploit this flaw to cause a denial of service by flooding the logging system with WARN() messages causing the initial domain to exhaust disk space (CVE-2015-8552 / XSA-157). The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application (CVE-2015-8660). For other upstream fixes, see the referenced changelogs. Other fixes in this update: * improve ath10k (QCA99X0, QCA988X, QCA6174) support (mga#16915) * silence a harmless warning on 32bit non-dt hardware (mga#17010) * fix regression with AlpsPS/2 ALPS DualPoint TouchPad of a Dell Latitude D600 (mga#17034)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0015.html");
script_cve_id("CVE-2015-1333","CVE-2015-4176","CVE-2015-4177","CVE-2015-4178","CVE-2015-4692","CVE-2015-4700","CVE-2015-5156","CVE-2015-5257","CVE-2015-5307","CVE-2015-5697","CVE-2015-5706","CVE-2015-5707","CVE-2015-6937","CVE-2015-7312","CVE-2015-7872","CVE-2015-7884","CVE-2015-7885","CVE-2015-8104","CVE-2015-8550","CVE-2015-8551","CVE-2015-8552","CVE-2015-8660");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0015");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.1.15~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
