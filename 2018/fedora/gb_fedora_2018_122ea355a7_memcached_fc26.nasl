###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_122ea355a7_memcached_fc26.nasl 9594 2018-04-25 02:13:41Z ckuersteiner $
#
# Fedora Update for memcached FEDORA-2018-122ea355a7
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
  script_oid("1.3.6.1.4.1.25623.1.0.874380");
  script_version("$Revision: 9594 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 04:13:41 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-22 08:39:21 +0200 (Sun, 22 Apr 2018)");
  script_cve_id("CVE-2018-1000115", "CVE-2017-9951");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for memcached FEDORA-2018-122ea355a7");
  script_tag(name: "summary", value: "Check the version of memcached");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "memcached is a high-performance, 
distributed memory object caching system, generic in nature, but intended 
for use in speeding up dynamic web applications by alleviating database load.
");
  script_tag(name: "affected", value: "memcached on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-122ea355a7");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U2D4OW2LSBUMSWFWMI3AS4KHFY7PXLT3");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.4.39~2.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
