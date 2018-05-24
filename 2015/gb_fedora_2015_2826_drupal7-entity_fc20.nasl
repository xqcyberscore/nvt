###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-entity FEDORA-2015-2826
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.869154");
  script_version("$Revision: 9939 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-23 16:50:30 +0200 (Wed, 23 May 2018) $");
  script_tag(name:"creation_date", value:"2015-04-01 07:20:42 +0200 (Wed, 01 Apr 2015)");
  script_cve_id("CVE-2014-1398", "CVE-2014-1399", "CVE-2014-1400");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7-entity FEDORA-2015-2826");
  script_tag(name: "summary", value: "Check the version of drupal7-entity");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This module extends the entity API of
Drupal core in order to provide a unified way to deal with entities and their
properties. Additionally, it provides an entity CRUD controller, which helps
simplifying the creation of new entity types.

This package provides the following Drupal modules:
* entity
* entity_token
");
  script_tag(name: "affected", value: "drupal7-entity on Fedora 20");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-2826");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-March/154070.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"drupal7-entity", rpm:"drupal7-entity~1.6~1.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
