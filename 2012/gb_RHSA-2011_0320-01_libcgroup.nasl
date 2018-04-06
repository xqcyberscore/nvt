###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libcgroup RHSA-2011:0320-01
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
tag_insight = "The libcgroup packages provide tools and libraries to control and monitor
  control groups.

  A heap-based buffer overflow flaw was found in the way libcgroup converted
  a list of user-provided controllers for a particular task into an array of
  strings. A local attacker could use this flaw to escalate their privileges
  via a specially-crafted list of controllers. (CVE-2011-1006)

  It was discovered that libcgroup did not properly check the origin of
  Netlink messages. A local attacker could use this flaw to send crafted
  Netlink messages to the cgrulesengd daemon, causing it to put processes
  into one or more existing control groups, based on the attacker's choosing,
  possibly allowing the particular tasks to run with more resources (memory,
  CPU, etc.) than originally intended. (CVE-2011-1022)

  Red Hat would like to thank Nelson Elhage for reporting the CVE-2011-1006
  issue.

  All libcgroup users should upgrade to these updated packages, which contain
  backported patches to correct these issues.";

tag_affected = "libcgroup on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-March/msg00011.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870680");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:45:59 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1006", "CVE-2011-1022");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2011:0320-01");
  script_name("RedHat Update for libcgroup RHSA-2011:0320-01");

  script_tag(name: "summary" , value: "Check for the Version of libcgroup");
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

  if ((res = isrpmvuln(pkg:"libcgroup", rpm:"libcgroup~0.36.1~6.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcgroup-debuginfo", rpm:"libcgroup-debuginfo~0.36.1~6.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcgroup-devel", rpm:"libcgroup-devel~0.36.1~6.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
