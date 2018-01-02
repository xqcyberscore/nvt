###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gimp RHSA-2012:1180-01
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
tag_insight = "The GIMP (GNU Image Manipulation Program) is an image composition and
  editing program.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the GIMP's GIF image format plug-in. An attacker could create a
  specially-crafted GIF image file that, when opened, could cause the GIF
  plug-in to crash or, potentially, execute arbitrary code with the
  privileges of the user running the GIMP. (CVE-2012-3481)

  A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL file
  format plug-in. An attacker could create a specially-crafted KiSS palette
  file that, when opened, could cause the CEL plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2012-3403)

  Red Hat would like to thank Matthias Weckbecker of the SUSE Security Team
  for reporting the CVE-2012-3481 issue.

  Users of the GIMP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The GIMP must be
  restarted for the update to take effect.";

tag_affected = "gimp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-August/msg00016.html");
  script_id(870810);
  script_version("$Revision: 8267 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 07:29:17 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-21 11:43:30 +0530 (Tue, 21 Aug 2012)");
  script_cve_id("CVE-2011-2896", "CVE-2012-3403", "CVE-2012-3481");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:1180-01");
  script_name("RedHat Update for gimp RHSA-2012:1180-01");

  script_tag(name: "summary" , value: "Check for the Version of gimp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.9~4.el6_3.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.6.9~4.el6_3.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-help-browser", rpm:"gimp-help-browser~2.6.9~4.el6_3.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.6.9~4.el6_3.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
