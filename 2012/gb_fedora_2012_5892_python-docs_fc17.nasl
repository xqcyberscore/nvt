###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for python-docs FEDORA-2012-5892
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
tag_insight = "The python-docs package contains documentation on the Python
  programming language and interpreter.

  Install the python-docs package if you'd like to use the documentation
  for the Python language.";

tag_affected = "python-docs on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-May/079569.html");
  script_id(864392);
  script_version("$Revision: 8336 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 08:01:48 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 10:07:36 +0530 (Thu, 30 Aug 2012)");
  script_cve_id("CVE-2012-1150", "CVE-2012-0845", "CVE-2011-3389");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2012-5892");
  script_name("Fedora Update for python-docs FEDORA-2012-5892");

  script_tag(name: "summary" , value: "Check for the Version of python-docs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.7.3~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
