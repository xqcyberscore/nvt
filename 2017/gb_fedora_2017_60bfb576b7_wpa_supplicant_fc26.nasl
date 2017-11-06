###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_60bfb576b7_wpa_supplicant_fc26.nasl 7658 2017-11-06 05:53:53Z teissa $
#
# Fedora Update for wpa_supplicant FEDORA-2017-60bfb576b7
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
  script_oid("1.3.6.1.4.1.25623.1.0.873510");
  script_version("$Revision: 7658 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-06 06:53:53 +0100 (Mon, 06 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-21 09:52:00 +0200 (Sat, 21 Oct 2017)");
  script_cve_id("CVE-2017-13082", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", 
                "CVE-2017-13081", "CVE-2017-13087", "CVE-2017-13088", "CVE-2017-13077");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for wpa_supplicant FEDORA-2017-60bfb576b7");
  script_tag(name: "summary", value: "Check the version of wpa_supplicant");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "wpa_supplicant is a WPA Supplicant for Linux, 
BSD and Windows with support for WPA and WPA2 (IEEE 802.11i / RSN). Supplicant is 
the IEEE 802.1X/WPA component that is used in the client stations. It implements 
key negotiation with a WPA Authenticator and it controls the roaming and IEEE 802.11
authentication/association of the wlan driver.");
  script_tag(name: "affected", value: "wpa_supplicant on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-60bfb576b7");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6QU3OES2BGSLFQGSDGNMTUWDQFC3JJ2Q");
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

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.6~11.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
