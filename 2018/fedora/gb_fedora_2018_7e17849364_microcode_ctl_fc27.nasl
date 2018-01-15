###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_7e17849364_microcode_ctl_fc27.nasl 8396 2018-01-12 11:39:41Z gveerendra $
#
# Fedora Update for microcode_ctl FEDORA-2018-7e17849364
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
  script_oid("1.3.6.1.4.1.25623.1.0.874001");
  script_version("$Revision: 8396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-12 12:39:41 +0100 (Fri, 12 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-11 07:41:04 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for microcode_ctl FEDORA-2018-7e17849364");
  script_tag(name: "summary", value: "Check the version of microcode_ctl");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The microcode_ctl utility is a companion 
to the microcode driver written by Tigran Aivazian  tigran(a)aivazian.fsnet.co.uk&amp gt .

The microcode update is volatile and needs to be uploaded on each system
boot i.e. it doesn&#39 t reflash your cpu permanently, reboot and it reverts
back to the old microcode.
");
  script_tag(name: "affected", value: "microcode_ctl on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-7e17849364");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NTF5B7F37IPDQ5QNTN26MLO4TLQLOSZ2");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~20.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
