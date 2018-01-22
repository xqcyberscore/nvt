###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pixman CESA-2013:1869 centos6 
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
  script_id(881849);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-12-23 12:44:57 +0530 (Mon, 23 Dec 2013)");
  script_cve_id("CVE-2013-6425");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for pixman CESA-2013:1869 centos6 ");

  tag_insight = "Pixman is a pixel manipulation library for the X Window System and Cairo.

An integer overflow, which led to a heap-based buffer overflow, was found
in the way pixman handled trapezoids. If a remote attacker could trick an 
application using pixman into rendering a trapezoid shape with specially 
crafted coordinates, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2013-6425)

Users are advised to upgrade to these updated packages, which contain a
backported patch to correct this issue. All applications using pixman 
must be restarted for this update to take effect.
";

  tag_affected = "pixman on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1869");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-December/020089.html");
  script_tag(name: "summary" , value: "Check for the Version of pixman");
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

  if ((res = isrpmvuln(pkg:"pixman", rpm:"pixman~0.26.2~5.1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pixman-devel", rpm:"pixman-devel~0.26.2~5.1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
