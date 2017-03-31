###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_datapower_xc10_dos_vuln.nasl 5534 2017-03-10 10:00:33Z teissa $
#
# IBM Websphere DataPower XC10 Denial of Service Vulnerability
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

CPE = "cpe:/h:ibm:websphere_datapower_xc10_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808184");
  script_version("$Revision: 5534 $");
  script_cve_id("CVE-2016-2870");
  script_bugtraq_id(91551);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-10 11:00:33 +0100 (Fri, 10 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-07-05 14:46:07 +0530 (Tue, 05 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("IBM Websphere DataPower XC10 Denial of Service Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with IBM Websphere 
  datapower XC10 and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"The flaw is due to a buffer
  overflow in the Command Line Interface (CLI).");

  script_tag(name: "impact" , value:"Successful exploitation will allow a remote
  attacker to cause a denial of service.
  
  Impact Level: Application");

  script_tag(name: "affected" , value:"IBM WebSphere DataPower XC10
  appliances 2.1 and 2.5");

  script_tag(name: "solution" , value:"Apply Fix pack from the below link
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg21983035");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21983035");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_datapower_xc10_detect.nasl");
  script_mandatory_keys("IBM/Websphere/Datapower/XC10/Version");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
xc_Ver = "";

## Get HTTP Port
if(!xc_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!xc_Ver = get_app_version(cpe:CPE, port:xc_port)){
  exit(0);
}

## Check IBMXC10 vulnerable versions
if(version_is_equal(version:xc_Ver, test_version:"2.1")||
   version_is_equal(version:xc_Ver, test_version:"2.5"))
{
  report = report_fixed_ver(installed_version:xc_Ver, fixed_version:"Apply fixpack IT15175");
  security_message(data:report, port:xc_port);
  exit(0);
}
