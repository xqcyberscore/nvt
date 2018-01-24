###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for lightdm FEDORA-2013-16388
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

if(description)
{
  script_id(866895);
  script_version("$Revision: 8509 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 07:57:46 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-09-18 10:08:17 +0530 (Wed, 18 Sep 2013)");
  script_cve_id("CVE-2013-4331");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Update for lightdm FEDORA-2013-16388");

  tag_insight = "LightDM is an X display manager that:
* Has a lightweight codebase
* Is standards compliant (PAM, ConsoleKit, etc)
* Has a well defined interface between the server and user interface
* Fully themeable (easiest with the webkit interface)
* Cross-desktop (greeters can be written in any toolkit)
";

  tag_affected = "lightdm on Fedora 19";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-16388");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115726.html");
  script_tag(name: "summary" , value: "Check for the Version of lightdm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"lightdm", rpm:"lightdm~1.6.2~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
