###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_ea44f172e3_chromium_fc26.nasl 8323 2018-01-08 14:50:05Z gveerendra $
#
# Fedora Update for chromium FEDORA-2017-ea44f172e3
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
  script_oid("1.3.6.1.4.1.25623.1.0.873977");
  script_version("$Revision: 8323 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 15:50:05 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-06 00:00:45 +0100 (Sat, 06 Jan 2018)");
  script_cve_id("CVE-2017-15412", "CVE-2017-15422", "CVE-2017-15407", "CVE-2017-15408", 
                "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15413", 
                "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418", 
                "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15423", "CVE-2017-15424", 
                "CVE-2017-15425", "CVE-2017-15426", "CVE-2017-15427", "CVE-2017-15429", 
                "CVE-2017-15398", "CVE-2017-15399", "CVE-2017-15386", "CVE-2017-15387", 
                "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391", 
                "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395", 
                "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", 
                "CVE-2017-5133", "CVE-2017-5131", "CVE-2017-5130", "CVE-2017-5132", 
                "CVE-2017-5129", "CVE-2017-5128");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2017-ea44f172e3");
  script_tag(name: "summary", value: "Check the version of chromium");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Chromium is an open-source web browser, 
powered by WebKit (Blink).");
  script_tag(name: "affected", value: "chromium on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-ea44f172e3");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TCX6RNONWP5H4F6S2D3GX2IVGKVND34L");
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

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~63.0.3239.108~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
