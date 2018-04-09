###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gimp CESA-2013:1778 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881826");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-04 10:08:35 +0530 (Wed, 04 Dec 2013)");
  script_cve_id("CVE-2012-5576", "CVE-2013-1913", "CVE-2013-1978");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for gimp CESA-2013:1778 centos6 ");

  tag_insight = "The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

A stack-based buffer overflow flaw, a heap-based buffer overflow, and an
integer overflow flaw were found in the way GIMP loaded certain X Window
System (XWD) image dump files. A remote attacker could provide a specially
crafted XWD image file that, when processed, would cause the XWD plug-in to
crash or, potentially, execute arbitrary code with the privileges of the
user running the GIMP. (CVE-2012-5576, CVE-2013-1913, CVE-2013-1978)

The CVE-2013-1913 and CVE-2013-1978 issues were discovered by Murray
McAllister of the Red Hat Security Response Team.

Users of the GIMP are advised to upgrade to these updated packages, which
correct these issues. The GIMP must be restarted for the update to take
effect.
";

  tag_affected = "gimp on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1778");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-December/020034.html");
  script_tag(name:"summary", value:"Check for the Version of gimp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.9~6.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.6.9~6.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-devel-tools", rpm:"gimp-devel-tools~2.6.9~6.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-help-browser", rpm:"gimp-help-browser~2.6.9~6.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.6.9~6.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}