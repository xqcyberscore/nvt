###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0237_1.nasl 8285 2018-01-04 06:29:16Z teissa $
#
# SuSE Update for nginx openSUSE-SU-2012:0237-1 (nginx)
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
tag_insight = "A flaw in the custom DNS resolver of nginx could lead to a
  heap based buffer overflow which could potentially allow
  attackers to execute arbitrary code or to cause a Denial of
  Service (bnc#731084, CVE-2011-4315).

  Special Instructions and Notes:

  Please reboot the system after installing this update.";

tag_affected = "nginx on openSUSE 11.4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850180);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 20:17:46 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-4315");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "openSUSE-SU", value: "2012:0237_1");
  script_name("SuSE Update for nginx openSUSE-SU-2012:0237-1 (nginx)");

  script_tag(name: "summary" , value: "Check for the Version of nginx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"nginx", rpm:"nginx~0.8~0.8.53~4.9.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
