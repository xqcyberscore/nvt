###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gimp RHSA-2011:0839-01
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

  A heap-based buffer overflow flaw was found in the GIMP's Paint Shop Pro
  (PSP) image file plug-in. An attacker could create a specially-crafted PSP
  image file that, when opened, could cause the PSP plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2010-4543)

  A stack-based buffer overflow flaw was found in the GIMP's Lightning,
  Sphere Designer, and Gfig image filters. An attacker could create a
  specially-crafted Lightning, Sphere Designer, or Gfig filter configuration
  file that, when opened, could cause the relevant plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2010-4540, CVE-2010-4541, CVE-2010-4542)

  Users of the GIMP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The GIMP must be
  restarted for the update to take effect.";

tag_affected = "gimp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-May/msg00030.html");
  script_id(870674);
  script_version("$Revision: 8336 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 08:01:48 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:45:23 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2011:0839-01");
  script_name("RedHat Update for gimp RHSA-2011:0839-01");

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

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.9~4.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.6.9~4.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-help-browser", rpm:"gimp-help-browser~2.6.9~4.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.6.9~4.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
