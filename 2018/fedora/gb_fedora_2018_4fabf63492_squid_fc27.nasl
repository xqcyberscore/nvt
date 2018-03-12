###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_4fabf63492_squid_fc27.nasl 9081 2018-03-12 07:31:35Z cfischer $
#
# Fedora Update for squid FEDORA-2018-4fabf63492
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874105");
  script_version("$Revision: 9081 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-12 08:31:35 +0100 (Mon, 12 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-07 08:08:58 +0100 (Wed, 07 Feb 2018)");
  script_cve_id("CVE-2018-1000024", "CVE-2018-1000027");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for squid FEDORA-2018-4fabf63492");
  script_tag(name: "summary", value: "Check the version of squid");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Squid is a high-performance proxy caching 
server for Web clients, supporting FTP, gopher, and HTTP data objects. Unlike 
traditional caching software, Squid handles all requests in a single,
non-blocking, I/O-driven process. Squid keeps meta data and especially
hot objects cached in RAM, caches DNS lookups, supports non-blocking
DNS lookups, and implements negative caching of failed requests.

Squid consists of a main server program squid, a Domain Name System
lookup program (dnsserver), a program for retrieving FTP data
(ftpget), and some management and client tools.
");
  script_tag(name: "affected", value: "squid on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-4fabf63492");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZB6HQWK7V2VCEVH35633BALACCWNOCMP");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~4.0.23~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
