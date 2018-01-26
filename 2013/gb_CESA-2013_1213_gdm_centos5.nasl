###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gdm CESA-2013:1213 centos5 
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
issue. The system must be rebooted for this update to take effect.";


if(description)
{
  script_id(881788);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-09-06 09:37:00 +0530 (Fri, 06 Sep 2013)");
  script_cve_id("CVE-2013-4169");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for gdm CESA-2013:1213 centos5 ");


  tag_affected = "gdm on CentOS 5";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1213");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-September/019925.html");
  script_tag(name: "summary" , value: "Check for the Version of gdm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.16.0~59.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-docs", rpm:"gdm-docs~2.16.0~59.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
