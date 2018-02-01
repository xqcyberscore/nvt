###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_dos_vuln01_jan16.nasl 8597 2018-01-31 08:42:52Z cfischer $
#
# IBM Websphere Apllication Server Denial Of Service Vulnerability 01 Jan16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806827");
  script_version("$Revision: 8597 $");
  script_cve_id("CVE-2014-0964");
  script_bugtraq_id(67322);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 09:42:52 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2016-01-19 13:15:39 +0530 (Tue, 19 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("IBM Websphere Apllication Server Denial Of Service Vulnerability 01 Jan16");

  script_tag(name: "summary" , value:"This host is installed with IBM Websphere 
  apllication server and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"The flaw is due to when running the
  Heartbleed scanning tools or if sending specially-crafted Heartbeat
  messages.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a remote
  attacker to cause a denial of service via crafted TLS traffic.  
  
  Impact Level: Application");

  script_tag(name: "affected" , value:"IBM WebSphere Application Server (WAS)
  6.1.0.0 through 6.1.0.47 and 6.0.2.0 through 6.0.2.43");

  script_tag(name: "solution" , value:"Apply Interim Fix PI16981 from the vendor
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg21671835");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.scaprepo.com/view.jsp?id=CVE-2014-0964");
  script_xref(name : "URL" , value : "http://www-304.ibm.com/support/docview.wss?uid=swg21673808");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wasVer = get_app_version(cpe:CPE, port:wasPort)){
  exit(0);
}

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.47"))
{
  fix = "Apply Interim Fix PI16981";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"6.0.2.0", test_version2:"6.0.2.43"))
{
  fix = "Apply Interim Fix PI17128";
  VULN = TRUE;  
}

if(VULN)
{
  report = 'Installed version: ' + wasVer + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report, port:wasPort);
  exit(0);
}
