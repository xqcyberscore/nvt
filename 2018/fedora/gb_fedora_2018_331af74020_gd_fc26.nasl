###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_331af74020_gd_fc26.nasl 9396 2018-04-09 04:18:59Z ckuersteiner $
#
# Fedora Update for gd FEDORA-2018-331af74020
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
  script_oid("1.3.6.1.4.1.25623.1.0.874328");
  script_version("$Revision: 9396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-09 06:18:59 +0200 (Mon, 09 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-06 10:08:56 +0200 (Fri, 06 Apr 2018)");
  script_cve_id("CVE-2018-5711");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gd FEDORA-2018-331af74020");
  script_tag(name: "summary", value: "Check the version of gd");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The gd graphics library allows your code 
to quickly draw images complete with lines, arcs, text, multiple colors, cut and 
paste from other images, and flood fills, and to write out the result as a PNG or
JPEG file. This is particularly useful in Web applications, where PNG and JPEG are 
two of the formats accepted for inline images by most browsers. Note that gd is 
not a paint program.
");
  script_tag(name: "affected", value: "gd on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-331af74020");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LMOPRS5MTB5DCE3HDR6RRSW4JEYAU5C6");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.2.5~2.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
