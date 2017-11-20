###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_efeb59171d_chromium_fc26.nasl 7801 2017-11-17 07:10:11Z asteins $
#
# Fedora Update for chromium FEDORA-2017-efeb59171d
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
  script_oid("1.3.6.1.4.1.25623.1.0.873498");
  script_version("$Revision: 7801 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-17 08:10:11 +0100 (Fri, 17 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-15 06:13:47 +0200 (Sun, 15 Oct 2017)");
  script_cve_id("CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114", 
                "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118", 
                "CVE-2017-5119", "CVE-2017-5120", "CVE-2017-5121", "CVE-2017-5122");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2017-efeb59171d");
  script_tag(name: "summary", value: "Check the version of chromium");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Chromium is an open-source web browser, 
powered by WebKit (Blink).");
  script_tag(name: "affected", value: "chromium on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-efeb59171d");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6NBTVXJ7RCR5WS3LY3FJHD5LC664S65G");
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

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~61.0.3163.100~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
