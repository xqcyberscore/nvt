###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for subscription-manager RHSA-2013:0788-01
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
tag_insight = "The subscription-manager packages provide programs and libraries to allow
  users to manage subscriptions and yum repositories from the Red Hat
  Entitlement platform.

  It was discovered that the rhn-migrate-classic-to-rhsm tool did not verify
  the Red Hat Network Classic server's X.509 certificate when migrating
  system profiles registered with Red Hat Network Classic to
  Certificate-based Red Hat Network. An attacker could use this flaw to
  conduct man-in-the-middle attacks, allowing them to obtain the user's Red
  Hat Network credentials. (CVE-2012-6137)

  This issue was discovered by Florian Weimer of the Red Hat Product Security
  Team.

  All users of subscription-manager are advised to upgrade to these updated
  packages, which contain a backported patch to fix this issue.";


tag_affected = "subscription-manager on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(870991);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-05-09 10:21:58 +0530 (Thu, 09 May 2013)");
  script_cve_id("CVE-2012-6137");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RedHat Update for subscription-manager RHSA-2013:0788-01");

  script_xref(name: "RHSA", value: "2013:0788-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-May/msg00003.html");
  script_tag(name: "summary" , value: "Check for the Version of subscription-manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"subscription-manager", rpm:"subscription-manager~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-debuginfo", rpm:"subscription-manager-debuginfo~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-firstboot", rpm:"subscription-manager-firstboot~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-gui", rpm:"subscription-manager-gui~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-migration", rpm:"subscription-manager-migration~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"subscription-manager", rpm:"subscription-manager~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-debuginfo", rpm:"subscription-manager-debuginfo~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-firstboot", rpm:"subscription-manager-firstboot~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-gui", rpm:"subscription-manager-gui~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-migration", rpm:"subscription-manager-migration~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
