###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_f941184db1_qemu_fc25.nasl 11317 2018-09-11 08:57:27Z asteins $
#
# Fedora Update for qemu FEDORA-2017-f941184db1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872918");
  script_version("$Revision: 11317 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 10:57:27 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-07-26 07:33:04 +0200 (Wed, 26 Jul 2017)");
  script_cve_id("CVE-2017-7718", "CVE-2016-9603", "CVE-2017-7377", "CVE-2017-7980", 
                "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", 
                "CVE-2017-9060", "CVE-2017-9310", "CVE-2017-9330", "CVE-2017-9374", 
                "CVE-2017-10806");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qemu FEDORA-2017-f941184db1");
  script_tag(name: "summary", value: "Check the version of qemu");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "QEMU is a generic and open source processor 
emulator which achieves a good emulation speed by using dynamic translation. 
QEMU has two operating modes:

 * Full system emulation. In this mode, QEMU emulates a full system (for
   example a PC), including a processor and various peripherials. It can be
   used to launch different Operating Systems without rebooting the PC or
   to debug system code.
 * User mode emulation. In this mode, QEMU can launch Linux processes compiled
   for one CPU on another CPU.

As QEMU requires no host kernel patches to run, it is safe and easy to use.
");
  script_tag(name: "affected", value: "qemu on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-f941184db1");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BBO4GN7KLLDD66JCIRPV4YS2EQFLOYLW");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.7.1~7.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
