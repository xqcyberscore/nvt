################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brother_hl_series_printer_xss_vuln.nasl 10197 2018-06-14 11:20:16Z asteins $
#
# Brother HL Series Printer Cross-Site Scripting Vulnerability
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

CPE = "cpe:/h:brother:hl-l2340d";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813391");
  script_version("$Revision: 10197 $");
  script_cve_id("CVE-2018-11581");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-14 13:20:16 +0200 (Thu, 14 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-06 15:18:41 +0530 (Wed, 06 Jun 2018)");
  script_name("Brother HL Series Printer Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running Brother HL Series Printer
  and is prone to a cross site scripting vulnerability.");
  
  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to am improper validation of
  url parameter to 'etc/loginerror.html'.");

  script_tag(name: "impact" , value:"Successful exploitation will allow an
  attacker to inject arbitrary html and script code into the web site. 
  This would alter the appearance and would make it possible to initiate further 
  attacks against site visitors.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Brother HL-L2340D and HL-L2380DW series 
  printers Firmware prior to 1.16.");

  script_tag(name: "solution" , value: "Update the printer to Firmware 1.16 or 
  later and set a new password. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value :"https://gist.github.com/huykha/409451e4b086bfbd55e28e7e803ae930");
  script_xref(name : "URL" , value :"http://support.brother.com");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_brother_hl_series_printer_detect.nasl");
  script_mandatory_keys("Brother/HL/Printer/model", "Brother/HL/Printer/version");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!brport = get_app_port(cpe:CPE))
{
  CPE = "cpe:/h:brother:hl-l2380dw";
  if(!brport = get_app_port(cpe:CPE)){
    exit(0);
  }
}

infos = get_app_version_and_location(cpe:CPE, port:brport, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.16"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.16", install_path:path);
  security_message(data:report, port:brport);
  exit(0);
}
exit(0);
