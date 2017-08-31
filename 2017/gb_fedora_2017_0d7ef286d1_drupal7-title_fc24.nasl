###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-title FEDORA-2017-0d7ef286d1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872348");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-02-20 11:38:35 +0100 (Mon, 20 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7-title FEDORA-2017-0d7ef286d1");
  script_tag(name: "summary", value: "Check the version of drupal7-title");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "While working on the new content translation system
(<a href='http://api.drupal.org/api/group/field_language/7' rel='nofollow'>http://api.drupal.org/api/group/field_language/7</a>) for Drupal 7, we (the Drupal
core i18n team) faced the need to convert node titles to the Field API in order
to make nodes fully translatable.

We were not able to make this happen in Drupal 7 core so we decided to find a
solution for this in contrib: the idea is replacing node titles with fields 
la Automatic Nodetitles (<a href='http://drupal.org/project/auto_nodetitle' rel='nofollow'>http://drupal.org/project/auto_nodetitle</a>).

This will be exploited by the related Entity Translation
(<a href='http://drupal.org/project/entity_translation' rel='nofollow'>http://drupal.org/project/entity_translation</a>) project.

This package provides the following Drupal module:
* title
");
  script_tag(name: "affected", value: "drupal7-title on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-0d7ef286d1");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HRRGQYLBJES4GF7YD62LRG6SI5II6SOH");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"drupal7-title", rpm:"drupal7-title~1.0~0.7.alpha9.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}