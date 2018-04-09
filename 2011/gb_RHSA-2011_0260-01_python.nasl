###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for python RHSA-2011:0260-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Python is an interpreted, interactive, object-oriented programming
  language.

  Multiple flaws were found in the Python rgbimg module. If an application
  written in Python was using the rgbimg module and loaded a
  specially-crafted SGI image file, it could cause the application to crash
  or, possibly, execute arbitrary code with the privileges of the user
  running the application. (CVE-2009-4134, CVE-2010-1449, CVE-2010-1450)
  
  This update also fixes the following bugs:
  
  * Python 2.3.4's time.strptime() function did not correctly handle the &quot;%W&quot;
  week number format string. This update backports the _strptime
  implementation from Python 2.3.6, fixing this issue. (BZ#436001)
  
  * Python 2.3.4's socket.htons() function returned partially-uninitialized
  data on IBM System z, generally leading to incorrect results. (BZ#513341)
  
  * Python 2.3.4's pwd.getpwuid() and grp.getgrgid() functions did not
  support the full range of user and group IDs on 64-bit architectures,
  leading to &quot;OverflowError&quot; exceptions for large input values. This update
  adds support for the full range of user and group IDs on 64-bit
  architectures. (BZ#497540)
  
  Users of Python should upgrade to these updated packages, which contain
  backported patches to correct these issues.";

tag_affected = "python on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-February/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870395");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-18 15:15:05 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2011:0260-01");
  script_cve_id("CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450");
  script_name("RedHat Update for python RHSA-2011:0260-01");

  script_tag(name:"summary", value:"Check for the Version of python");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.3.4~14.9.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.3.4~14.9.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.3.4~14.9.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.3.4~14.9.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.3.4~14.9.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.3.4~14.9.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
