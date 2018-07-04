###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_44f8a7454d_qemu_fc28.nasl 10387 2018-07-04 05:21:03Z cfischer $
#
# Fedora Update for qemu FEDORA-2018-44f8a7454d
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874719");
  script_version("$Revision: 10387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 07:21:03 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-22 06:02:21 +0200 (Fri, 22 Jun 2018)");
  script_cve_id("CVE-2018-3639");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qemu FEDORA-2018-44f8a7454d");
  script_tag(name:"summary", value:"Check the version of qemu");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"QEMU is a generic and open source processor emulator which achieves a good
emulation speed by using dynamic translation. QEMU has two operating modes:

 * Full system emulation. In this mode, QEMU emulates a full system (for
   example a PC), including a processor and various peripherials. It can be
   used to launch different Operating Systems without rebooting the PC or
   to debug system code.
 * User mode emulation. In this mode, QEMU can launch Linux processes compiled
   for one CPU on another CPU.

As QEMU requires no host kernel patches to run, it is safe and easy to use.
");
  script_tag(name:"affected", value:"qemu on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-44f8a7454d");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6XRSKIFF4UITPQLVDCD6CI3M5MR5TN4Q");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.11.1~3.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}