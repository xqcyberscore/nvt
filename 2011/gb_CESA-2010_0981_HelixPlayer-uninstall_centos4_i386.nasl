###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for HelixPlayer-uninstall CESA-2010:0981 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Helix Player is a media player.

  Multiple security flaws were discovered in RealPlayer. Helix Player and
  RealPlayer share a common source code base; therefore, some of the flaws
  discovered in RealPlayer may also affect Helix Player. Some of these flaws
  could, when opening, viewing, or playing a malicious media file or stream,
  lead to arbitrary code execution with the privileges of the user running
  Helix Player. (CVE-2010-2997, CVE-2010-4375, CVE-2010-4378, CVE-2010-4379,
  CVE-2010-4382, CVE-2010-4383, CVE-2010-4384, CVE-2010-4385, CVE-2010-4386,
  CVE-2010-4392)
  
  The Red Hat Security Response Team is unable to properly determine the
  impact or fix all of these issues in Helix Player, due to the source code
  for RealPlayer being unavailable.
  
  Due to the security concerns this update removes the HelixPlayer package
  from Red Hat Enterprise Linux 4. Users wishing to continue to use Helix
  Player should download it directly from https://player.helixcommunity.org";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "HelixPlayer-uninstall on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-January/017237.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880498");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2010:0981");
  script_cve_id("CVE-2010-2997", "CVE-2010-4375", "CVE-2010-4378", "CVE-2010-4379", "CVE-2010-4382",
                "CVE-2010-4383", "CVE-2010-4384", "CVE-2010-4385", "CVE-2010-4386", "CVE-2010-4392");
  script_name("CentOS Update for HelixPlayer-uninstall CESA-2010:0981 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of HelixPlayer-uninstall");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"HelixPlayer-uninstall", rpm:"HelixPlayer-uninstall~1.0.6~3.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"HelixPlayer", rpm:"HelixPlayer~1.0.6~3.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
