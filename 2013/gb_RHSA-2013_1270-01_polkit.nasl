###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for polkit RHSA-2013:1270-01
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871041");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:44:34 +0530 (Tue, 24 Sep 2013)");
  script_cve_id("CVE-2013-4288");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for polkit RHSA-2013:1270-01");

  tag_insight = "PolicyKit is a toolkit for defining and handling authorizations.

A race condition was found in the way the PolicyKit pkcheck utility
checked process authorization when the process was specified by its process
ID via the --process option. A local user could use this flaw to bypass
intended PolicyKit authorizations and escalate their privileges.
(CVE-2013-4288)

Note: Applications that invoke pkcheck with the --process option need to be
modified to use the pid,pid-start-time,uid argument for that option, to
allow pkcheck to check process authorization correctly.

Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
reporting this issue.

All polkit users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The system must be rebooted for
this update to take effect.
";

  tag_affected = "polkit on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2013:1270-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-September/msg00030.html");
  script_tag(name: "summary" , value: "Check for the Version of polkit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

  if ((res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.96~5.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-debuginfo", rpm:"polkit-debuginfo~0.96~5.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-devel", rpm:"polkit-devel~0.96~5.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-docs", rpm:"polkit-docs~0.96~5.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-desktop-policy", rpm:"polkit-desktop-policy~0.96~5.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
