###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gc CESA-2013:1500 centos6 
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
  script_id(881818);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-11-08 10:44:37 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2012-2673");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("CentOS Update for gc CESA-2013:1500 centos6 ");

  tag_insight = "gc is a Boehm-Demers-Weiser conservative garbage collector for C and C++.

It was discovered that gc's implementation of the malloc() and calloc()
routines did not properly perform parameter sanitization when allocating
memory. If an application using gc did not implement application-level
validity checks for the malloc() and calloc() routines, a remote attacker
could provide specially crafted application-specific input, which, when
processed by the application, could lead to an application crash or,
potentially, arbitrary code execution with the privileges of the user
running the application. (CVE-2012-2673)

Users of gc are advised to upgrade to these updated packages, which contain
backported patches to correct this issue. Applications using gc must be
restarted for the update to take effect.
";

  tag_affected = "gc on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1500");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-November/020015.html");
  script_tag(name: "summary" , value: "Check for the Version of gc");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"gc", rpm:"gc~7.1~12.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gc-devel", rpm:"gc-devel~7.1~12.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
