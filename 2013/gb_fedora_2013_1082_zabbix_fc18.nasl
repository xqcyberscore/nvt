###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for zabbix FEDORA-2013-1082
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Zabbix is software that monitors numerous parameters of a network and the
  health and integrity of servers. Zabbix uses a flexible notification mechanism
  that allows users to configure e-mail based alerts for virtually any event.
  This allows a fast reaction to server problems. Zabbix offers excellent
  reporting and data visualization features based on the stored data.
  This makes Zabbix ideal for capacity planning.

  Zabbix supports both polling and trapping. All Zabbix reports and statistics,
  as well as configuration parameters are accessed through a web-based front end.
  A web-based front end ensures that the status of your network and the health of
  your servers can be assessed from any location. Properly configured, Zabbix can
  play an important role in monitoring IT infrastructure. This is equally true
  for small organizations with a few servers and for large companies with a
  multitude of servers.";


tag_affected = "zabbix on Fedora 18";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097656.html");
  script_id(865267);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-31 09:24:59 +0530 (Thu, 31 Jan 2013)");
  script_cve_id("CVE-2013-1364");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2013-1082");
  script_name("Fedora Update for zabbix FEDORA-2013-1082");

  script_tag(name: "summary" , value: "Check for the Version of zabbix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~2.0.4~3.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
