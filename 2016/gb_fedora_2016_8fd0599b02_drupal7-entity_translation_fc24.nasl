###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-entity_translation FEDORA-2016-8fd0599b02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809115");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-08-14 05:51:59 +0200 (Sun, 14 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7-entity_translation FEDORA-2016-8fd0599b02");
  script_tag(name: "summary", value: "Check the version of drupal7-entity_translation");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Allows (fieldable) entities to be translated
  into different languages, by introducing entity/field translation for the new
  translatable fields capability in Drupal 7.
  Maintained by the Drupal core i18n team.

  This project does not replace the Internationalization
  (<a href='http://drupal.org/project/i18n' rel='nofollow'>http://drupal.org/project/i18n</a>)
  project, which focuses on enabling a full
  multilingual workflow for site admins/builders. Some features, e.g. content
  language negotiation or taxonomy translation, might overlap but most of them
  are unrelated.

  This package provides the following Drupal modules:
  * entity_translation
  * entity_translation_i18n_menu (requires install of drupal7-i18n)
  * entity_translation_upgrade");

  script_tag(name: "affected", value: "drupal7-entity_translation on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-8fd0599b02");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JMPMSGN2ER2GA7L357UPLFKFP7P7IKYO");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"drupal7-entity_translation", rpm:"drupal7-entity_translation~1.0~0.9.beta5.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
