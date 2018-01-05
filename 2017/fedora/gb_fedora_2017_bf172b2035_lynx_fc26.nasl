###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_bf172b2035_lynx_fc26.nasl 8291 2018-01-04 09:51:36Z asteins $
#
# Fedora Update for lynx FEDORA-2017-bf172b2035
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
  script_oid("1.3.6.1.4.1.25623.1.0.873961");
  script_version("$Revision: 8291 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 10:51:36 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-29 08:05:45 +0100 (Fri, 29 Dec 2017)");
  script_cve_id("CVE-2017-1000211");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for lynx FEDORA-2017-bf172b2035");
  script_tag(name: "summary", value: "Check the version of lynx");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Lynx is a text-based Web browser. Lynx 
does not display any images, but it does support frames, tables, and most 
other HTML tags. One advantage Lynx has over graphical browsers is speed  
Lynx starts and exits quickly and swiftly displays web pages.
");
  script_tag(name: "affected", value: "lynx on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-bf172b2035");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/W3C6N3YOAXQYEXLPKXBUEVYDHYVHFAKX");
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

  if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.9~0.20.dev16.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
