# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0386.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130007");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:25 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0386");
script_tag(name: "insight", value: "This kernel update provides an upgrade to the upstream 4.1 longterm kernel series, currently based on 4.1.8 and resolves atleast the following security issues: It was found that the Linux kernel's keyring implementation would leak memory when adding a key to a keyring via the add_key() function. A local attacker could use this flaw to exhaust all available memory on the system. (CVE-2015-1333) A flaw was found in the Linux kernel where the deletion of a file or directory could trigger an unmount and reveal data under a mount point. This flaw was inadvertently introduced with the new feature of being able to lazily unmount a mount tree when using file system user namespaces. (CVE-2015-4176) A flaw was discovered in the kernel's collect_mounts function. If the kernel audit subsystem called collect_mounts to audit an unmounted path, it could panic the system. With this flaw, an unprivileged user could call umount (MNT_DETACH) to launch a denial-of-service attack. (CVE-2015-4177) A flaw was found in the Linux kernel which is related to the user namespace lazily unmounting file systems. The fs_pin struct has two members (m_list and s_list) which are usually initialized on use in the pin_insert_group function. However, these members might go unmodified; in this case, the system panics when it attempts to destroy or free them. This flaw could be used to launch a denial-of-service attack. (CVE-2015-4178) A DoS flaw was found for a Linux kernel built for the x86 architecture which had the KVM virtualization support(CONFIG_KVM) enabled. The kernel would be vulnerable to a NULL pointer dereference flaw in Linux kernel's kvm_apic_has_events() function while doing an ioctl. An unprivileged user able to access the /dev/kvm device could use this flaw to crash the system kernel. (CVE-2015-4692) A flaw was found in the kernel's implementation of the Berkeley Packet Filter (BPF). A local attacker could craft BPF code to crash the system by creating a situation in which the JIT compiler would fail to correctly optimize the JIT image on the last pass. This would lead to the CPU executing instructions that were not part of the JIT code. (CVE-2015-4700) The get_bitmap_file function in drivers/md/md.c in the Linux kernel before 4.1.6 does not initialize a certain bitmap data structure, which allows local users to obtain sensitive information from kernel memory via a GET_BITMAP_FILE ioctl call. (CVE-2015-5697) Use-after-free vulnerability in the path_openat function in fs/namei.c in the Linux kernel 3.x and 4.x before 4.0.4 allows local users to cause a denial of service or possibly have unspecified other impact via O_TMPFILE filesystem operations that leverage a duplicate cleanup operation. (CVE-2015-5706) It was discovered that an integer overflow error existed in the SCSIgeneric (sg) driver in the Linux kernel. A local attacker with writepermission to a SCSI generic device could use this to cause a denial of service (system crash) or potentially escalate their privileges. (CVE-2015-5707) Additionally the following packages have been updated to add or improve support for the 4.1 series kernels: btrfs-progs, iproute2, xtables-addons, nvidia304, nvidia340, kernel-firmware-nonfree, radeon-firmware. For other changes, see the referenced changelogs:"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0386.html");
script_cve_id("CVE-2015-1333","CVE-2015-4176","CVE-2015-4177","CVE-2015-4178","CVE-2015-4692","CVE-2015-4700","CVE-2015-5697","CVE-2015-5706","CVE-2015-5707","CVE-2015-7312");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0386");
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
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.1.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.1.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20150722~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"btrfs-progs", rpm:"btrfs-progs~4.1.2~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"iproute2", rpm:"iproute2~4.1.1~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"xtables-addons", rpm:"xtables-addons~2.7~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.7~4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-firmware-nonfree", rpm:"kernel-firmware-nonfree~20150824~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"radeon-firmware", rpm:"radeon-firmware~20150824~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.248~36.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~15.200.1046~5.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nvidia304", rpm:"nvidia304~304.125~5.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.125~41.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nvidia340", rpm:"nvidia340~340.76~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia340", rpm:"kmod-nvidia340~340.76~31.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~346.82~3.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
