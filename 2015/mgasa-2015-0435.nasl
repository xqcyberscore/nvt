# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0435.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131108");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-11-08 13:02:05 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0435");
script_tag(name: "insight", value: "This kernel update is based on the upstream 4.1.12 longterm kernel and fixes atleast the following security issue: Moein Ghasemzadeh discovered that the USB WhiteHEAT serial driver contained hardcoded attributes about the USB devices. An attacker could construct a fake WhiteHEAT USB device that, when inserted, causes a denial of service (system crash) (CVE-2015-5257). It also fixes various upstream bugs, for more info see the referenced changelogs. Other fixes in this update: * improve ath10k (QCA99X0, QCA988X, QCA6174) support (mga#16915) * silence a harmless warning on 32bit non-dt hardware (mga#17010) * fix regression with AlpsPS/2 ALPS DualPoint TouchPad of a Dell Latitude D600 (mga#17034) * kernel-firmware-nonfee: - Add firmware for mwlwifi - add firmware for QCA99X0 hw2.0, QCA988X hw2.0, QCA6174 hw2.1/3.0 (ath10k) - brcmfmac: firmware refresh for BCM43602 PCIE devices * iwlwifi-agn-ucode: - Add firmware for Intel Bluetooth 7265 (D1) - Update firmware for Intel Bluetooth 7265 (C0/D0) - Update firmware for Intel Bluetooth 7260 (B3/B4/B5/B6)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0435.html");
script_cve_id("CVE-2015-5257");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0435");
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
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.1.12~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.1.12~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.0.8~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.0.8~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.7~5.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.271~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~15.200.1046~6.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.128~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia340", rpm:"kmod-nvidia340~340.93~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~346.96~2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-firmware-nonfree", rpm:"kernel-firmware-nonfree~20151018~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
