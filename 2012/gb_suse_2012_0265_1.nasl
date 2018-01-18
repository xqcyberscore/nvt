###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0265_1.nasl 8448 2018-01-17 16:18:06Z teissa $
#
# SuSE Update for flash-player openSUSE-SU-2012:0265-1 (flash-player)
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
tag_insight = "flash-player was updated to the security update to
  11.1.102.62.

  It fixes lots of security issues, some already exploited in
  the wild.

  Details can be found on:
  https://www.adobe.com/support/security/bulletins/apsb12-03.html

  These vulnerabilities could cause a crash and potentially
  allow an attacker to take control of the affected system.
  This update also resolves a universal cross-site scripting
  vulnerability that could be used to take actions on a
  user's behalf on any website or webmail provider, if the
  user visits a malicious website. There are reports that
  this vulnerability (CVE-2012-0767) is being exploited in
  the wild in active targeted attacks designed to trick the
  user into clicking on a malicious link delivered in an
  email message (Internet Explorer on Windows only).";

tag_affected = "flash-player on openSUSE 11.4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850292);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 23:36:37 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2012-0751", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754", "CVE-2012-0755", "CVE-2012-0756", "CVE-2012-0767");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "openSUSE-SU", value: "2012:0265_1");
  script_name("SuSE Update for flash-player openSUSE-SU-2012:0265-1 (flash-player)");

  script_tag(name: "summary" , value: "Check for the Version of flash-player");
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

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.1.102.62~0.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
