###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gdm RHSA-2013:1213-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871035");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-06 09:36:25 +0530 (Fri, 06 Sep 2013)");
  script_cve_id("CVE-2013-4169");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for gdm RHSA-2013:1213-01");

  tag_insight = "The GNOME Display Manager (GDM) provides the graphical login screen, shown
shortly after boot up, log out, and when user-switching.

A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged user
could use this flaw to perform a symbolic link attack, giving them write
access to any file, allowing them to escalate their privileges to root.
(CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the initscripts
package was modified to create the affected directory safely during the
system boot process. Therefore, this update will appear on all systems,
however systems without GDM installed are not affected by this flaw.

Red Hat would like to thank the researcher with the nickname vladz for
reporting this issue.

All users should upgrade to these updated packages, which correct this
issue. The system must be rebooted for this update to take effect.
";

  tag_affected = "gdm on Red Hat Enterprise Linux (v. 5 server)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2013:1213-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-September/msg00017.html");
  script_tag(name: "summary" , value: "Check for the Version of gdm");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.16.0~59.el5_9.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-debuginfo", rpm:"gdm-debuginfo~2.16.0~59.el5_9.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-docs", rpm:"gdm-docs~2.16.0~59.el5_9.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"initscripts", rpm:"initscripts~8.45.42~2.el5_9.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"initscripts-debuginfo", rpm:"initscripts-debuginfo~8.45.42~2.el5_9.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
