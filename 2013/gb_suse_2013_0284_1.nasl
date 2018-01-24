###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_0284_1.nasl 8509 2018-01-24 06:57:46Z teissa $
#
# SuSE Update for flash-player openSUSE-SU-2013:0284-1 (flash-player)
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

tag_affected = "flash-player on openSUSE 11.4";
tag_insight = "Adobe Flash Player was updated to  11.2.202.262 to fix
  various security issues and bugs.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.opensuse.org/opensuse-security-announce/2013-02/msg00006.html");
  script_id(850396);
  script_version("$Revision: 8509 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 07:57:46 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:40 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2013-0633", "CVE-2013-0634");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "openSUSE-SU", value: "2013:0284_1");
  script_name("SuSE Update for flash-player openSUSE-SU-2013:0284-1 (flash-player)");

  script_tag(name: "summary" , value: "Check for the Version of flash-player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.262~43.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.262~43.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-kde4", rpm:"flash-player-kde4~11.2.202.262~43.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
