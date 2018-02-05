###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libarchive FEDORA-2013-4522
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_affected = "libarchive on Fedora 17";
tag_insight = "Libarchive is a programming library that can create and read several different
  streaming archive formats, including most popular tar variants, several cpio
  formats, and both BSD and GNU ar variants. It can also write share archives and
  read ISO9660 CDROM images and ZIP archives.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865561);
  script_version("$Revision: 8650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:59 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-04-15 10:11:36 +0530 (Mon, 15 Apr 2013)");
  script_cve_id("CVE-2013-0211");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Update for libarchive FEDORA-2013-4522");

  script_xref(name: "FEDORA", value: "2013-4522");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/101876.html");
  script_tag(name: "summary" , value: "Check for the Version of libarchive");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.0.4~3.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
