###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for NetworkManager RHSA-2011:0930-01
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
tag_insight = "NetworkManager is a network link manager that attempts to keep a wired or
  wireless network connection active at all times.

  It was found that NetworkManager did not properly enforce PolicyKit
  settings controlling the permissions to configure wireless network sharing.
  A local, unprivileged user could use this flaw to bypass intended PolicyKit
  restrictions, allowing them to enable wireless network sharing.
  (CVE-2011-2176)

  Users of NetworkManager should upgrade to these updated packages, which
  contain a backported patch to correct this issue. Running instances of
  NetworkManager must be restarted (&quot;service NetworkManager restart&quot;) for
  this update to take effect.";

tag_affected = "NetworkManager on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-July/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870703");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:50:35 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-2176");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_xref(name: "RHSA", value: "2011:0930-01");
  script_name("RedHat Update for NetworkManager RHSA-2011:0930-01");

  script_tag(name: "summary" , value: "Check for the Version of NetworkManager");
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

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.8.1~9.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-debuginfo", rpm:"NetworkManager-debuginfo~0.8.1~9.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.8.1~9.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.8.1~9.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
