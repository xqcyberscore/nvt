###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kdenetwork RHSA-2011:0465-01
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
tag_insight = "The kdenetwork packages contain networking applications for the K Desktop
  Environment (KDE).

  A directory traversal flaw was found in the way KGet, a download manager,
  handled the &quot;file&quot; element in Metalink files. An attacker could use this
  flaw to create a specially-crafted Metalink file that, when opened, would
  cause KGet to overwrite arbitrary files accessible to the user running
  KGet. (CVE-2011-1586)

  Users of kdenetwork should upgrade to these updated packages, which contain
  a backported patch to resolve this issue. The desktop must be restarted
  (log out, then log back in) for this update to take effect.";

tag_affected = "kdenetwork on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-April/msg00024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870602");
  script_version("$Revision: 8649 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:32:45 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1586", "CVE-2010-1000");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "RHSA", value: "2011:0465-01");
  script_name("RedHat Update for kdenetwork RHSA-2011:0465-01");

  script_tag(name: "summary" , value: "Check for the Version of kdenetwork");
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

  if ((res = isrpmvuln(pkg:"kdenetwork", rpm:"kdenetwork~4.3.4~11.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-debuginfo", rpm:"kdenetwork-debuginfo~4.3.4~11.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-devel", rpm:"kdenetwork-devel~4.3.4~11.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-libs", rpm:"kdenetwork-libs~4.3.4~11.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
