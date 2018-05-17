###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_1361f39801_ckeditor_fc26.nasl 9863 2018-05-16 12:29:42Z santu $
#
# Fedora Update for ckeditor FEDORA-2018-1361f39801
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
  script_oid("1.3.6.1.4.1.25623.1.0.874431");
  script_version("$Revision: 9863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-16 14:29:42 +0200 (Wed, 16 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-12 06:07:12 +0200 (Sat, 12 May 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ckeditor FEDORA-2018-1361f39801");
  script_tag(name:"summary", value:"Check the version of ckeditor");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"CKEditor is a text editor to be used inside 
web pages. It&#39 s a WYSIWYG editor,
which means that the text being edited on it looks as similar as possible to
the results users have when publishing it. It brings to the web common editing
features found on desktop editing applications like Microsoft Word and
OpenOffice.
");
  script_tag(name:"affected", value:"ckeditor on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-1361f39801");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OZIFRMCURGFT2GUTFK2JIJFQDR72EBMY");
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

  if ((res = isrpmvuln(pkg:"ckeditor", rpm:"ckeditor~4.9.2~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
