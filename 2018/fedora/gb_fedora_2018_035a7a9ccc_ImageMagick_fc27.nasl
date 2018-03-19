###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_035a7a9ccc_ImageMagick_fc27.nasl 9132 2018-03-19 11:22:37Z santu $
#
# Fedora Update for ImageMagick FEDORA-2018-035a7a9ccc
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
  script_oid("1.3.6.1.4.1.25623.1.0.874244");
  script_version("$Revision: 9132 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-19 12:22:37 +0100 (Mon, 19 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-19 08:31:16 +0100 (Mon, 19 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ImageMagick FEDORA-2018-035a7a9ccc");
  script_tag(name: "summary", value: "Check the version of ImageMagick");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "ImageMagick is an image display and 
manipulation tool for the X Window System. ImageMagick can read and write JPEG, TIFF, 
PNM, GIF, and Photo CD image formats. It can resize, rotate, sharpen, color
reduce, or add special effects to an image, and when finished you can either save 
the completed work in the original format or a different one. ImageMagick also 
includes command line programs for creating animated or transparent .gifs, creating 
composite images, creating thumbnail images, and more.

ImageMagick is one of your choices if you need a program to manipulate
and display images. If you want to develop your own applications
which use ImageMagick code or APIs, you need to install
ImageMagick-devel as well.
");
  script_tag(name: "affected", value: "ImageMagick on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-035a7a9ccc");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/J3FMLBOKBCT4YVJKWP4TYIRITAY5IVEO");
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

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.9.9.38~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
