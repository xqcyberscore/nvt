###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for qemu FEDORA-2008-2001
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "QEMU is a generic and open source processor emulator which achieves a good
  emulation speed by using dynamic translation. QEMU has two operating modes:

   * Full system emulation. In this mode, QEMU emulates a full system (for
     example a PC), including a processor and various peripherials. It can be
     used to launch different Operating Systems without rebooting the PC or
     to debug system code.
   * User mode emulation. In this mode, QEMU can launch Linux processes compiled
     for one CPU on another CPU.
  
  As QEMU requires no host kernel patches to run, it is safe and easy to use.";

tag_affected = "qemu on Fedora 7";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-February/msg00857.html");
  script_id(860163);
  script_version("$Revision: 3216 $");
  script_cve_id("CVE-2008-0928");
  script_tag(name:"last_modification", value:"$Date: 2016-05-03 15:18:38 +0200 (Tue, 03 May 2016) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:22:52 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_xref(name: "FEDORA", value: "2008-2001");
  script_name( "Fedora Update for qemu FEDORA-2008-2001");

  script_summary("Check for the Version of qemu");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~0.9.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
