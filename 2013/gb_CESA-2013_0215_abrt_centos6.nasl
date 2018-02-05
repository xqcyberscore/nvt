###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for abrt CESA-2013:0215 centos6 
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
tag_insight = "ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
  defects in applications and to create a bug report with all the information
  needed by a maintainer to fix it. It uses a plug-in system to extend its
  functionality. libreport provides an API for reporting different problems
  in applications to different bug targets, such as Bugzilla, FTP, and Trac.

  It was found that the
  /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache tool did not
  sufficiently sanitize its environment variables. This could lead to Python
  modules being loaded and run from non-standard directories (such as /tmp/).
  A local attacker could use this flaw to escalate their privileges to that
  of the abrt user. (CVE-2012-5659)
  
  A race condition was found in the way ABRT handled the directories used to
  store information about crashes. A local attacker with the privileges of
  the abrt user could use this flaw to perform a symbolic link attack,
  possibly allowing them to escalate their privileges to root.
  (CVE-2012-5660)
  
  Red Hat would like to thank Martin Carpenter of Citco for reporting the
  CVE-2012-5660 issue. CVE-2012-5659 was discovered by Miloslav Trma of Red
  Hat.
  
  All users of abrt and libreport are advised to upgrade to these updated
  packages, which correct these issues.";


tag_affected = "abrt on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-February/019226.html");
  script_id(881588);
  script_version("$Revision: 8650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:59 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-02-04 09:55:16 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2012-5659", "CVE-2012-5660");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2013:0215");
  script_name("CentOS Update for abrt CESA-2013:0215 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of abrt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.0.8~6.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
