###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for WebCalendar FEDORA-2012-1934
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
tag_affected = "WebCalendar on Fedora 16";
tag_insight = "WebCalendar is a PHP-based calendar application that can be configured as a
  single-user calendar, a multi-user calendar for groups of users, or as an
  event calendar viewable by visitors. MySQL, PostgreSQL, Oracle, DB2,
  Interbase, MS SQL Server, or ODBC is required.
    WebCalendar can be setup in a variety of ways, such as...
   * A schedule management system for a single person
   * A schedule management system for a group of people, allowing one or
     more assistants to manage the calendar of another user
   * An events schedule that anyone can view, allowing visitors to submit
     new events
   * A calendar server that can be viewed with iCal-compliant calendar
     applications like Mozilla Sunbird, Apple iCal or GNOME Evolution or
     RSS-enabled applications like Firefox, Thunderbird, RSSOwl, or
     FeedDemon, or BlogExpress.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-February/073762.html");
  script_id(864034);
  script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 8313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 08:02:11 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-04-02 13:04:15 +0530 (Mon, 02 Apr 2012)");
  script_cve_id("CVE-2012-0846");
  script_xref(name: "FEDORA", value: "2012-1934");
  script_name("Fedora Update for WebCalendar FEDORA-2012-1934");

  script_tag(name: "summary" , value: "Check for the Version of WebCalendar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

  if ((res = isrpmvuln(pkg:"WebCalendar", rpm:"WebCalendar~1.2.4~3.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
