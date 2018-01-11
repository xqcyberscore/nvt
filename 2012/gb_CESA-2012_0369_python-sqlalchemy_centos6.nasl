###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for python-sqlalchemy CESA-2012:0369 centos6 
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
tag_insight = "SQLAlchemy is an Object Relational Mapper (ORM) that provides a flexible,
  high-level interface to SQL databases.

  It was discovered that SQLAlchemy did not sanitize values for the limit and
  offset keywords for SQL select statements. If an application using
  SQLAlchemy accepted values for these keywords, and did not filter or
  sanitize them before passing them to SQLAlchemy, it could allow an attacker
  to perform an SQL injection attack against the application. (CVE-2012-0805)
  
  All users of python-sqlalchemy are advised to upgrade to this updated
  package, which contains a patch to correct this issue. All running
  applications using SQLAlchemy must be restarted for this update to take
  effect.";

tag_affected = "python-sqlalchemy on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-March/018474.html");
  script_id(881193);
  script_version("$Revision: 8352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 08:01:57 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:40:02 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0805");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2012:0369");
  script_name("CentOS Update for python-sqlalchemy CESA-2012:0369 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of python-sqlalchemy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"python-sqlalchemy", rpm:"python-sqlalchemy~0.5.5~3.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
