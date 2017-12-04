###############################################################################
# $Id: gb_tor_anonymity_feature_bypass_vuln.nasl 7968 2017-12-01 08:26:28Z asteins $
#
# Tor Browser Anonymity Feature Bypass Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:tor:tor_browser";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811988");
  script_version("$Revision: 7968 $");
  script_cve_id("CVE-2017-16541");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 09:26:28 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-09 16:08:09 +0530 (Thu, 09 Nov 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Tor Browser Anonymity Feature Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Tor Browser
  and is prone to anonymity feature bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling
  'file://' links which will cause Tor Browser to not to go through the network
  of Tor relays.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive information that may aid in launching
  further attacks. 

  Impact Level: Application");

  script_tag(name:"affected", value:"Tor Browser before 7.0.9");

  script_tag(name:"solution", value:"Upgrade to version 7.0.9 or later.
  For updates refer to https://www.torproject.org/download/download-easy.html.en");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://www.bleepingcomputer.com/news/security/tormoil-vulnerability-leaks-real-ip-address-from-tor-browser-users");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tor_browser_detect_lin.nasl");
  script_mandatory_keys("TorBrowser/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

torbVer = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
torbVer = infos['version'];
torPath = infos['location'];

if(version_is_less(version:torbVer, test_version:"7.0.9"))
{
  report = report_fixed_ver( installed_version:torbVer, fixed_version:"7.0.9", install_path:torPath);
  security_message(data:report);
  exit(0);
}
exit(0);
