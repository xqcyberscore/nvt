# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0369.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130022");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:37 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0369");
script_tag(name: "insight", value: "Updated qemu packages fix security vulnerabilities: Qemu emulator built with the RTL8139 emulation support is vulnerable to an information leakage flaw. It could occur while processing network packets under RTL8139 controller's C+ mode of operation. A guest user could use this flaw to read uninitialised Qemu heap memory up to 65K bytes (CVE-2015-5165). Qinghao Tang and Mr. Zuozhi discovered that QEMU incorrectly handled memory in the VNC display driver. A malicious guest could use this issue to cause a denial of service, or possibly execute arbitrary code on the host as the user running the QEMU process (CVE-2015-5225). - Mageia 5 only Qemu emulator built with the e1000 NIC emulation support is vulnerable to an infinite loop issue. It could occur while processing transmit descriptor data when sending a network packet. A privileged user inside guest could use this flaw to crash the Qemu instance resulting in DoS (CVE-2015-6815). Qemu emulator built with the IDE disk and CD/DVD-ROM emulation support is vulnerable to a divide by zero issue. It could occur while executing an IDE command WIN_READ_NATIVE_MAX to determine the maximum size of a drive. A privileged user inside guest could use this flaw to crash the Qemu instance resulting in DoS (CVE-2015-6855)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0369.html");
script_cve_id("CVE-2015-5165","CVE-2015-5225","CVE-2015-6815","CVE-2015-6855");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0369");
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
if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.1.3~2.6.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
