###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plex_media_server_mult_vuln.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# Plex Media Server Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:plex:plex_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805226");
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2014-9181", "CVE-2014-9304");
  script_bugtraq_id(65881);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-12-22 17:44:41 +0530 (Mon, 22 Dec 2014)");
  script_name("Plex Media Server Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Plex Media
  Server and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple errors are due to,
  - An error in '/system/proxy' which fails to validate pre-authentication
  user requests.
  - Input appended to the URL after 'manage', 'web' and 'resources' is not
  properly sanitised before being used to read files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose certain sensitive information and bypass certain
  security restrictions.

  Impact Level: Application");

  script_tag(name:"affected", value:"Plex Media Server versions
  0.9.9.2.374-aa23a69 and prior.");

  script_tag(name:"solution", value:"Upgrade to Plex Media Server version
  0.9.9.3 or later. For updates refer http://www.plex.tv");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57205");
  script_xref(name : "URL" , value : "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140228-1_Plex_Media_Server_Authentication_bypass_local_file_disclosure_v10.txt");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_dependencies("gb_plex_media_server_remote_detect.nasl");
  script_mandatory_keys("plex_media_server/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

# Variable Initialization
plexPort = "";
plexVer = "";

## get the port
if(!plexPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!plexVer = get_app_version(cpe:CPE, port:plexPort)){
  exit(0);
}

##Check if version is less than 0.9.9.3
if(version_is_less(version:plexVer, test_version:"0.9.9.3"))
{
  security_message(port:plexPort);
  exit(0);
}
