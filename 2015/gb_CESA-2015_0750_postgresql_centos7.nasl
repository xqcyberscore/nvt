###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql CESA-2015:0750 centos7 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882148");
  script_version("$Revision: 6657 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:50:44 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-04-01 07:24:59 +0200 (Wed, 01 Apr 2015)");
  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for postgresql CESA-2015:0750 centos7 ");
  script_tag(name: "summary", value: "Check the version of postgresql");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "PostgreSQL is an advanced object-relational database management system
(DBMS).

An information leak flaw was found in the way the PostgreSQL database
server handled certain error messages. An authenticated database user could
possibly obtain the results of a query they did not have privileges to
execute by observing the constraint violation error messages produced when
the query was executed. (CVE-2014-8161)

A buffer overflow flaw was found in the way PostgreSQL handled certain
numeric formatting. An authenticated database user could use a specially
crafted timestamp formatting template to cause PostgreSQL to crash or,
under certain conditions, execute arbitrary code with the permissions of
the user running PostgreSQL. (CVE-2015-0241)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto module.
An authenticated database user could use this flaw to cause PostgreSQL to
crash or, potentially, execute arbitrary code with the permissions of the
user running PostgreSQL. (CVE-2015-0243)

A flaw was found in the way PostgreSQL handled certain errors that were
generated during protocol synchronization. An authenticated database user
could use this flaw to inject queries into an existing connection.
(CVE-2015-0244)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Stephen Frost as the original reporter of
CVE-2014-8161  Andres Freund, Peter Geoghegan, Bernd Helmle, and Noah Misch
as the original reporters of CVE-2015-0241  Marko Tiikkaja as the original
reporter of CVE-2015-0243  and Emil Lenngren as the original reporter of
CVE-2015-0244.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the postgresql
service is running, it will be automatically restarted after installing
this update.
");
  script_tag(name: "affected", value: "postgresql on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "CESA", value: "2015:0750");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2015-April/021032.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-upgrade", rpm:"postgresql-upgrade~9.2.10~2.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}