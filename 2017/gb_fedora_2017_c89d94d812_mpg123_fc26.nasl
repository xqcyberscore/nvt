###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_c89d94d812_mpg123_fc26.nasl 7593 2017-10-27 10:22:01Z cfischer $
#
# Fedora Update for mpg123 FEDORA-2017-c89d94d812
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
  script_oid("1.3.6.1.4.1.25623.1.0.873442");
  script_version("$Revision: 7593 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-27 12:22:01 +0200 (Fri, 27 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-09-21 07:36:51 +0200 (Thu, 21 Sep 2017)");
  script_cve_id("CVE-2017-10683", "CVE-2017-11126", "CVE-2017-9545", "CVE-2017-12797");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mpg123 FEDORA-2017-c89d94d812");
  script_tag(name: "summary", value: "Check the version of mpg123");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Real time MPEG 1.0/2.0/2.5 audio player/decoder for layers 1, 2 and 3 (most
commonly MPEG 1.0 layer 3 aka MP3), as well as re-usable decoding and output
libraries.
");
  script_tag(name: "affected", value: "mpg123 on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-c89d94d812");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/B66YFWMEQIKVZJIZU5FOUVNGUJWNV23V");
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

  if ((res = isrpmvuln(pkg:"mpg123", rpm:"mpg123~1.25.6~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
