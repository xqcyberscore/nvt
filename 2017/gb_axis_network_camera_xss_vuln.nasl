###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_network_camera_xss_vuln.nasl 7610 2017-11-01 13:14:39Z jschulte $
#
# Axis Network Camera Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:axis:network_camera";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811276");
  script_version("$Revision: 7610 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-01 14:14:39 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-08-07 18:10:07 +0530 (Mon, 07 Aug 2017)");
  script_name("Axis Network Camera Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is running Axis Network Cameras and is
  prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an improper sanitization
  of input to 'admin.shtml' page.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute javascript code in the context of current user.

  Impact Level: Application");

  script_tag(name:"affected", value:"Axis Camera model 2100 Network Camera 2.43");

  script_tag(name:"solution", value:"No solution or patch is available as of
  1st Nov, 2017. The product is considered end-of-life and a fix is unlikely.
  For updates refer to http://www.axis.com");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/143657");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_network_cameras_ftp_detect.nasl");
  script_mandatory_keys("axis/camera/version", "axis/camera/model");
  script_require_ports("Services/ftp", 21, "Services/www", 80);
  exit(0);
}

## The script code starts here
include("host_details.inc");
include("version_func.inc");

## Variable initialization
model = "";
axport = "";
report = "";

## Get Port
if(!axport = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version and model
if(!(version = get_app_version(cpe:CPE, port:axport)) ||
   !(model = get_kb_item("axis/camera/model"))){
  exit(0);
}

##Check for vulnerable version
if(model == "2100" && version == "2.43")
{
  report = report_fixed_ver(installed_version:model + " " + version, fixed_version:"None Available");
  security_message(data:report, port:axport);
  exit(0);
}
exit(0);
