###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql CESA-2012:0677 centos5 
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
tag_insight = "PostgreSQL is an advanced object-relational database management system
  (DBMS).

  The pg_dump utility inserted object names literally into comments in the
  SQL script it produces. An unprivileged database user could create an
  object whose name includes a newline followed by an SQL command. This SQL
  command might then be executed by a privileged user during later restore of
  the backup dump, allowing privilege escalation. (CVE-2012-0868)
  
  CREATE TRIGGER did not do a permissions check on the trigger function to
  be called. This could possibly allow an authenticated database user to
  call a privileged trigger function on data of their choosing.
  (CVE-2012-0866)
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. If the postgresql
  service is running, it will be automatically restarted after installing
  this update.";

tag_affected = "postgresql on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-May/018647.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881159");
  script_version("$Revision: 8649 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:25:39 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0866", "CVE-2012-0868");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2012:0677");
  script_name("CentOS Update for postgresql CESA-2012:0677 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of postgresql");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.1.23~4.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
