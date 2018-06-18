###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_cec96a9c41_nghttp2_fc27.nasl 10224 2018-06-15 14:29:06Z cfischer $
#
# Fedora Update for nghttp2 FEDORA-2018-cec96a9c41
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
  script_oid("1.3.6.1.4.1.25623.1.0.874374");
  script_version("$Revision: 10224 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 16:29:06 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-04-21 09:10:24 +0200 (Sat, 21 Apr 2018)");
  script_cve_id("CVE-2018-1000168");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nghttp2 FEDORA-2018-cec96a9c41");
  script_tag(name: "summary", value: "Check the version of nghttp2");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This package contains the HTTP/2 client, 
server and proxy programs.");
  script_tag(name: "affected", value: "nghttp2 on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-cec96a9c41");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ALABVVYQAK4DCJ5BMBL2PRF2ZHZTDC2V");
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

  if ((res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.31.1~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
