###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_ba81e4e4a0_gd_fc27.nasl 9288 2018-04-04 06:15:11Z asteins $
#
# Fedora Update for gd FEDORA-2018-ba81e4e4a0
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
  script_oid("1.3.6.1.4.1.25623.1.0.874302");
  script_version("$Revision: 9288 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 08:15:11 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-29 08:48:24 +0200 (Thu, 29 Mar 2018)");
  script_cve_id("CVE-2018-5711");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gd FEDORA-2018-ba81e4e4a0");
  script_tag(name: "summary", value: "Check the version of gd");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The gd graphics library allows your code 
to quickly draw images complete with lines, arcs, text, multiple colors, cut 
and paste from other images, and flood fills, and to write out the result as a 
PNG or JPEG file. This is particularly useful in Web applications, where PNG
and JPEG are two of the formats accepted for inline images by most browsers. 
Note that gd is not a paint program.
");
  script_tag(name: "affected", value: "gd on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-ba81e4e4a0");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I3QDHFDY3AGLLKLLK7ZCF4BLMHSI66UV");
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

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.2.5~3.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
