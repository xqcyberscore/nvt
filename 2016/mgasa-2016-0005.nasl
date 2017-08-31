# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0005.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131182");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-01-14 07:28:55 +0200 (Thu, 14 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0005");
script_tag(name: "insight", value: "This kernel update is based on upstream 4.1.15 longterm kernel and fixes the following security issues: The __rds_conn_create function in net/rds/connection.c in the Linux kernel through 4.2.3 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact by using a socket that was not properly bound (CVE-2015-6937). The key_gc_unused_keys function in security/keys/gc.c in the Linux kernel through 4.2.6 allows local users to cause a denial of service (OOPS) via crafted keyctl commands (CVE-2015-7872). The vivid_fb_ioctl function in drivers/media/platform/vivid/vivid-osd.c in the Linux kernel through 4.3.3 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel memory via a crafted application (CVE-2015-7884). The dgnc_mgmt_ioctl function in drivers/staging/dgnc/dgnc_mgmt.c in the Linux kernel through 4.3.3 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel memory via a crafted application (CVE-2015-7885). Felix Wilhelm discovered a race condition in the Xen paravirtualized drivers which can cause double fetch vulnerabilities. An attacker in the paravirtualized guest could exploit this flaw to cause a denial of service (crash the host) or potentially execute arbitrary code on the host (CVE-2015-8550 / XSA-155). Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not perform sanity checks on the device's state. An attacker could exploit this flaw to cause a denial of service (NULL dereference) on the host (CVE-2015-8551 / XSA-157). Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not perform sanity checks on the device's state. An attacker could exploit this flaw to cause a denial of service by flooding the logging system with WARN() messages causing the initial domain to exhaust disk space (CVE-2015-8552 / XSA-157). The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application (CVE-2015-8660). For other fixes in this update, see the referenced changelogs."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0005.html");
script_cve_id("CVE-2015-6937","CVE-2015-7872","CVE-2015-7884","CVE-2015-7885","CVE-2015-8550","CVE-2015-8551","CVE-2015-8552","CVE-2015-8660");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0005");
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
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.1.15~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.1.15~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.7~7.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.271~4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~15.200.1046~8.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.128~4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia340", rpm:"kmod-nvidia340~340.93~4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~346.96~4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
