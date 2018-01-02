###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for phpMyAdmin FEDORA-2011-11477
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
tag_insight = "phpMyAdmin is a tool written in PHP intended to handle the administration of
  MySQL over the World Wide Web. Most frequently used operations are supported
  by the user interface (managing databases, tables, fields, relations, indexes,
  users, permissions), while you still have the ability to directly execute any
  SQL statement.

  Features include an intuitive web interface, support for most MySQL features
  (browse and drop databases, tables, views, fields and indexes, create, copy,
  drop, rename and alter databases, tables, fields and indexes, maintenance
  server, databases and tables, with proposals on server configuration, execute,
  edit and bookmark any SQL-statement, even batch-queries, manage MySQL users
  and privileges, manage stored procedures and triggers), import data from CSV
  and SQL, export data to various formats: CSV, SQL, XML, PDF, OpenDocument Text
  and Spreadsheet, Word, Excel, LATEX and others, administering multiple servers,
  creating PDF graphics of your database layout, creating complex queries using
  Query-by-example (QBE), searching globally in a database or a subset of it,
  transforming stored data into any format using a set of predefined functions,
  like displaying BLOB-data as image or download-link and much more...";

tag_affected = "phpMyAdmin on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-September/065854.html");
  script_id(864007);
  script_version("$Revision: 8265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 07:29:23 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-04-02 12:53:31 +0530 (Mon, 02 Apr 2012)");
  script_cve_id("CVE-2011-3181");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2011-11477");
  script_name("Fedora Update for phpMyAdmin FEDORA-2011-11477");

  script_tag(name: "summary" , value: "Check for the Version of phpMyAdmin");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~3.4.4~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
