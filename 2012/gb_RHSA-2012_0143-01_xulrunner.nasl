###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xulrunner RHSA-2012:0143-01
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
tag_insight = "XULRunner provides the XUL Runtime environment for applications using the
  Gecko layout engine.

  A heap-based buffer overflow flaw was found in the way XULRunner handled
  PNG (Portable Network Graphics) images. A web page containing a malicious
  PNG image could cause an application linked against XULRunner (such as
  Firefox) to crash or, potentially, execute arbitrary code with the
  privileges of the user running the application. (CVE-2011-3026)

  All XULRunner users should upgrade to these updated packages, which correct
  this issue. After installing the update, applications using XULRunner must
  be restarted for the changes to take effect.";

tag_affected = "xulrunner on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00039.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870546");
  script_version("$Revision: 9416 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-10 09:34:03 +0200 (Tue, 10 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:55:36 +0530 (Tue, 21 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:0143-01");
  script_name("RedHat Update for xulrunner RHSA-2012:0143-01");
  script_cve_id("CVE-2011-3026");
  script_tag(name: "summary" , value: "Check for the Version of xulrunner");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.2.26~2.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~1.9.2.26~2.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.2.26~2.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
