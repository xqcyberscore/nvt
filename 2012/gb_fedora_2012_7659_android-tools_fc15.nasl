###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for android-tools FEDORA-2012-7659
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The Android Debug Bridge (ADB) is used to:

  - keep track of all Android devices and emulators instances
    connected to or running on a given host developer machine

  - implement various control commands (e.g. &quot;adb shell&quot;, &quot;adb pull&quot;, etc.)
    for the benefit of clients (command-line users, or helper programs like
    DDMS). These commands are what is called a 'service' in ADB.

  Fastboot is used to manipulate the flash partitions of the Android phone.
  It can also boot the phone using a kernel image or root filesystem image
  which reside on the host machine rather than in the phone flash.
  In order to use it, it is important to understand the flash partition
  layout for the phone.
  The fastboot program works in conjunction with firmware on the phone
  to read and write the flash partitions. It needs the same USB device
  setup between the host and the target phone as adb.";

tag_affected = "android-tools on Fedora 15";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-May/080657.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864241");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-22 10:09:31 +0530 (Tue, 22 May 2012)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2012-7659");
  script_name("Fedora Update for android-tools FEDORA-2012-7659");

  script_tag(name: "summary" , value: "Check for the Version of android-tools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"android-tools", rpm:"android-tools~20120510gitd98c87c~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
