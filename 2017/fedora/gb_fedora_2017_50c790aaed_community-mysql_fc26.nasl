###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_50c790aaed_community-mysql_fc26.nasl 7739 2017-11-13 05:04:18Z teissa $
#
# Fedora Update for community-mysql FEDORA-2017-50c790aaed
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873571");
  script_version("$Revision: 7739 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-13 06:04:18 +0100 (Mon, 13 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-07 11:28:28 +0100 (Tue, 07 Nov 2017)");
  script_cve_id("CVE-2017-10155", "CVE-2017-10227", "CVE-2017-10268", "CVE-2017-10276", 
                "CVE-2017-10279", "CVE-2017-10283", "CVE-2017-10286", "CVE-2017-10294", 
                "CVE-2017-10314", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for community-mysql FEDORA-2017-50c790aaed");
  script_tag(name: "summary", value: "Check the version of community-mysql");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "MySQL is a multi-user, multi-threaded SQL 
database server. MySQL is a client/server implementation consisting of a server 
daemon (mysqld) and many different client programs and libraries. The base 
package contains the standard MySQL client programs and generic MySQL files.");
  script_tag(name: "affected", value: "community-mysql on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-50c790aaed");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KKFUAIRME6IO6MUVOFTLZZ3PSMYD2ULB");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~5.7.20~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
