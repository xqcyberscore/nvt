###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for zabbix FEDORA-2012-12488
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
tag_insight = "ZABBIX is software that monitors numerous parameters of a network and
  the health and integrity of servers. ZABBIX uses a flexible
  notification mechanism that allows users to configure e-mail based
  alerts for virtually any event.  This allows a fast reaction to server
  problems. ZABBIX offers excellent reporting and data visualisation
  features based on the stored data. This makes ZABBIX ideal for
  capacity planning.

  ZABBIX supports both polling and trapping. All ZABBIX reports and
  statistics, as well as configuration parameters are accessed through a
  web-based front end. A web-based front end ensures that the status of
  your network and the health of your servers can be assessed from any
  location. Properly configured, ZABBIX can play an important role in
  monitoring IT infrastructure. This is equally true for small
  organisations with a few servers and for large companies with a
  multitude of servers.";

tag_affected = "zabbix on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-August/085818.html");
  script_id(864689);
  script_version("$Revision: 8245 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 07:29:59 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-09-04 11:34:47 +0530 (Tue, 04 Sep 2012)");
  script_cve_id("CVE-2012-3435", "CVE-2011-4615");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2012-12488");
  script_name("Fedora Update for zabbix FEDORA-2012-12488");

  script_tag(name: "summary" , value: "Check for the Version of zabbix");
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

  if ((res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~1.8.15~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
