###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_5bf744beee_gd_fc28.nasl 11972 2018-10-19 05:34:20Z cfischer $
#
# Fedora Update for gd FEDORA-2018-5bf744beee
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
  script_oid("1.3.6.1.4.1.25623.1.0.875035");
  script_version("$Revision: 11972 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 07:34:20 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-09-06 07:31:03 +0200 (Thu, 06 Sep 2018)");
  script_cve_id("CVE-2018-1000222");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gd FEDORA-2018-5bf744beee");
  script_tag(name:"summary", value:"Check the version of gd");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
 on the target host.");
  script_tag(name:"insight", value:"The gd graphics library allows your code to
 quickly draw images complete with lines, arcs, text, multiple colors, cut and
 paste from other images, and flood fills, and to write out the result as a PNG
 or JPEG file. This is particularly useful in Web applications, where PNG and
 JPEG are two of the formats accepted for inline images by most browsers. Note
 that gd is not a paint program.
");
  script_tag(name:"affected", value:"gd on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-5bf744beee");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M2IH7H4SEFQS2YIKRK4AEB3MGPKOM4GW");
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

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.2.5~6.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
