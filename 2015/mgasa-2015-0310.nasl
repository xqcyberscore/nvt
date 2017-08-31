# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0310.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130069");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:42:20 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0310");
script_tag(name: "insight", value: "Matt Tait discovered that QEMU incorrectly handled the virtual PCNET driver. A malicious guest could use this issue to cause a denial of service, or possibly execute arbitrary code on the host as the user running the QEMU process (CVE-2015-3209). Kurt Seifried discovered that QEMU incorrectly handled certain temporary files. A local attacker could use this issue to cause a denial of service (CVE-2015-4037). Jan Beulich discovered that the QEMU Xen code incorrectly restricted write access to the host MSI message data field. A malicious guest could use this issue to cause a denial of service (CVE-2015-4103). Jan Beulich discovered that the QEMU Xen code incorrectly restricted access to the PCI MSI mask bits. A malicious guest could use this issue to cause a denial of service (CVE-2015-4104). Jan Beulich discovered that the QEMU Xen code incorrectly handled MSI-X error messages. A malicious guest could use this issue to cause a denial of service (CVE-2015-4105). Jan Beulich discovered that the QEMU Xen code incorrectly restricted write access to the PCI config space. A malicious guest could use this issue to cause a denial of service, obtain sensitive information, or possibly execute arbitrary code (CVE-2015-4106). A heap buffer overflow flaw was found in the way QEMU's IDE subsystem handled I/O buffer access while processing certain ATAPI commands. A privileged guest user in a guest with the CDROM drive enabled could potentially use this flaw to execute arbitrary code on the host with the privileges of the host's QEMU process corresponding to the guest (CVE-2015-5154). An out-of-bounds memory access flaw, leading to memory corruption or possibly an information leak, was found in QEMU's pit_ioport_read() function. A privileged guest user in a QEMU guest, which had QEMU PIT emulation enabled, could potentially, in rare cases, use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process (CVE-2015-3214). Qemu emulator built with the virtio-serial vmchannel support is vulnerable to a buffer overflow issue. It could occur while exchanging virtio control messages between guest & the host. A malicious guest could use this flaw to corrupt few bytes of Qemu memory area, potentially crashing the Qemu process (CVE-2015-5745)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0310.html");
script_cve_id("CVE-2015-3209","CVE-2015-3214","CVE-2015-4037","CVE-2015-4103","CVE-2015-4104","CVE-2015-4105","CVE-2015-4106","CVE-2015-5154","CVE-2015-5745");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0310");
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
if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.1.3~2.3.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
