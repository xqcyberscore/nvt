###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_c708c044e3_chromium_fc25.nasl 9681 2018-05-02 02:36:53Z ckuersteiner $
#
# Fedora Update for chromium FEDORA-2017-c708c044e3
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
  script_oid("1.3.6.1.4.1.25623.1.0.873355");
  script_version("$Revision: 9681 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-02 04:36:53 +0200 (Wed, 02 May 2018) $");
  script_tag(name:"creation_date", value:"2017-09-10 07:31:11 +0200 (Sun, 10 Sep 2017)");
  script_cve_id("CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", 
                "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098", 
                "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", 
                "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-7000", "CVE-2017-5105", 
                "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", 
                "CVE-2017-5110");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2017-c708c044e3");
  script_tag(name: "summary", value: "Check the version of chromium");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Chromium is an open-source web browser, 
powered by WebKit (Blink).");
  script_tag(name: "affected", value: "chromium on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-c708c044e3");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OG6ZGRJ567UV2ZLLJTS3P7KCLJ3WIAGJ");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~60.0.3112.113~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
