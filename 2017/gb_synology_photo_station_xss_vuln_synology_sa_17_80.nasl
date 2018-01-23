###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_photo_station_xss_vuln_synology_sa_17_80.nasl 8493 2018-01-23 06:43:13Z ckuersteiner $
#
# Synology Photo Station Cross-Site Scripting Vulnerability (Synology_SA_17_80)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:synology:synology_photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812358");
  script_version("$Revision: 8493 $");
  script_cve_id("CVE-2017-12072");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:43:13 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-21 15:28:05 +0530 (Thu, 21 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Synology Photo Station Cross-Site Scripting Vulnerability (Synology_SA_17_80)");

  script_tag(name: "summary" , value:"This host is installed with Synology
  Photo Station and is prone to cross-site scripting vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to insufficient
  validation of input passed to 'PixlrEditorHandler.php' script via the 'id'
  parameter.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  authenticated users to inject arbitrary web scripts or HTML code.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Synology Photo Station before before
  6.8.0-3456");

  script_tag(name: "solution" , value:"Upgrade to Photo Station version 
  6.8.0-3456 or above.
  For updates refer to https://www.synology.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.synology.com/en-global/support/security/Synology_SA_17_80");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_mandatory_keys("synology_photo_station/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

synport = "";
synVer = "";
synpath = "";

if (!synport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:synport, exit_no_version:TRUE)) exit(0);
synVer = infos['version'];
synpath = infos['location'];

if(version_is_less(version:synVer, test_version: "6.8.0-3456"))
{
  report = report_fixed_ver(installed_version:synVer, fixed_version:"6.8.0-3456", install_path:synpath);
  security_message(port:synport, data: report);
  exit(0);
}
exit(0);
