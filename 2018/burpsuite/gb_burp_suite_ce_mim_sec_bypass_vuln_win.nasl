################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_burp_suite_ce_mim_sec_bypass_vuln_win.nasl 10371 2018-06-29 13:27:39Z santu $
#
# Burp Suite CE Man in the Middle Security Bypass Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

CPE = "cpe:/a:portswigger:burp_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813611");
  script_version("$Revision: 10371 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-29 15:27:39 +0200 (Fri, 29 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 16:08:53 +0530 (Tue, 19 Jun 2018)");
  script_name("Burp Suite CE Man in the Middle Security Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Burp Suite
  Community Edition and is prone to man in the middle security bypass vulnerability.");
  
  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to Burp sends a couple 
  of HTTPS requests without verifying the server certificate.");

  script_tag(name: "impact" , value:"Successful exploitation will allows
  a man in the middle to intercept communication and inject new data.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Burp Suite Community Edition 1.7.32 
  and 1.7.33.");

  script_tag(name: "solution" , value: "Upgrade to version 1.7.34 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value :"http://releases.portswigger.net/2018/06/1734.html");
  script_xref(name : "URL" , value :"https://portswigger.net");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_burp_suite_ce_detect_win.nasl");
  script_mandatory_keys("BurpSuite/CommunityEdition/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(vers == "1.7.32" || vers == "1.7.33")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.7.34", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
