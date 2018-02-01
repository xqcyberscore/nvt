###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dap_1360_mult_csrf_vuln.nasl 8598 2018-01-31 09:59:32Z cfischer $
#
# D-Link DAP-1360 Multiple CSRF Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/h:dlink:dap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810235");
  script_version("$Revision: 8598 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 10:59:32 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2016-12-10 10:43:14 +0530 (Sat, 10 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("D-Link DAP-1360 Multiple CSRF Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with D-Link DAP
  device and is prone to multiple Cross-Site Request Forgery vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed model with the help of
  detect nvt and check the model is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple cross
  site request forgery errors in Wi-Fi - WPS method.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to change method in Connection - WPS Method, change parameter 
  WPS Enable, reset to unconfigured and read configuration in Information
  - Refresh.

  Impact Level: Application");

  script_tag(name:"affected", value:"D-Link DAP-1360, Firmware 1.0.0.
  This model with other firmware versions also must be vulnerable.");

  script_tag(name: "solution" , value:"Update to DAP-1360/A/E1A (f/w version 2.5.4).  For updates refer to http://www.dlink.com.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2016/Dec/9");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_detect.nasl");
  script_mandatory_keys("dlink/dap/model", "dlink/dap/firmver");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!dlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!model = get_kb_item("dlink/dap/model")){
  exit(0);
}

if(!version =  get_app_version(cpe:CPE, port:dlPort)){
  exit(0);
}

## Check for vulnerable model
if(model =~ "1360$" && version_is_less(version:version, test_version:"2.5.4"))
{
  report = report_fixed_ver(installed_version:version, fixed_version: "2.5.4");
  security_message( port:dlPort, data:report);
  exit(0);
}
