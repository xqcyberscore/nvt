###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql84 CESA-2012:1263 centos5 
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

  It was found that the optional PostgreSQL xml2 contrib module allowed local
  files and remote URLs to be read and written to with the privileges of the
  database server when parsing Extensible Stylesheet Language Transformations
  (XSLT). An unprivileged database user could use this flaw to read and write
  to local files (such as the database's configuration files) and remote URLs
  they would otherwise not have access to by issuing a specially-crafted SQL
  query. (CVE-2012-3488)
  
  It was found that the &quot;xml&quot; data type allowed local files and remote URLs
  to be read with the privileges of the database server to resolve DTD and
  entity references in the provided XML. An unprivileged database user could
  use this flaw to read local files they would otherwise not have access to
  by issuing a specially-crafted SQL query. Note that the full contents of
  the files were not returned, but portions could be displayed to the user
  via error messages. (CVE-2012-3489)
  
  Red Hat would like to thank the PostgreSQL project for reporting these
  issues. Upstream acknowledges Peter Eisentraut as the original reporter of
  CVE-2012-3488, and Noah Misch as the original reporter of CVE-2012-3489.
  
  These updated packages upgrade PostgreSQL to version 8.4.13. Refer to the
  PostgreSQL Release Notes for a list of changes:
  
  <a  rel= &qt nofollow &qt  href= &qt http://www.postgresql.org/docs/8.4/static/release-8-4-13.html &qt >http://www.postgresql.org/docs/8.4/static/release-8-4-13.html</a>
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct these issues. If the postgresql service is running, it will
  be automatically restarted after installing this update.";

tag_affected = "postgresql84 on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-September/018870.html");
  script_id(881490);
  script_version("$Revision: 8352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 08:01:57 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:44:12 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_xref(name: "CESA", value: "2012:1263");
  script_name("CentOS Update for postgresql84 CESA-2012:1263 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of postgresql84");
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

  if ((res = isrpmvuln(pkg:"postgresql84", rpm:"postgresql84~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-contrib", rpm:"postgresql84-contrib~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-devel", rpm:"postgresql84-devel~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-docs", rpm:"postgresql84-docs~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-libs", rpm:"postgresql84-libs~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plperl", rpm:"postgresql84-plperl~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plpython", rpm:"postgresql84-plpython~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-pltcl", rpm:"postgresql84-pltcl~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-python", rpm:"postgresql84-python~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-server", rpm:"postgresql84-server~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-tcl", rpm:"postgresql84-tcl~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-test", rpm:"postgresql84-test~8.4.13~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
