###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-field_permissions FEDORA-2012-1390
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The Field Permissions module is a drop-in replacement for the Content
  Permissions module shipped with CCK.

  It allows site administrators to set field-level permissions to edit or
  view CCK fields in any node, and optionally (new feature compared to Content
  Permissions module), edit field during node creation, and edit or view
  permissions for nodes owned by the current user.

  Permissions for each field are not created by default. Instead,
  administrators can enable these permissions explicitly for the fields
  where this feature is needed.";

tag_affected = "drupal7-field_permissions on Fedora 15";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-February/073477.html");
  script_id(863734);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:54:38 +0530 (Tue, 21 Feb 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2012-1390");
  script_name("Fedora Update for drupal7-field_permissions FEDORA-2012-1390");

  script_tag(name: "summary" , value: "Check for the Version of drupal7-field_permissions");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"drupal7-field_permissions", rpm:"drupal7-field_permissions~1.0~0.2.beta2.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
