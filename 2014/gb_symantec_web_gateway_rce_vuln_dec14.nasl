###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_rce_vuln_dec14.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Symantec Web Gateway Unspecified Remote Command Execution Vulnerability - Dec14
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

CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805229");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-7285");
  script_bugtraq_id(71620);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-12-23 15:04:28 +0530 (Tue, 23 Dec 2014)");
  script_name("Symantec Web Gateway Unspecified Remote Command Execution Vulnerability - Dec14");

  script_tag(name:"summary", value:"This host is installed with Symantec Web
  Gateway and is prone to remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The error exists due to an unspecified
  error related to the appliance management console");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to compromise a vulnerable system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Symantec Web Gateway prior to version
  5.2.2");

  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version
  5.2.2 or later. For updates refer http://www.symantec.com/web-gateway/");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/60795");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20141216_00");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_mandatory_keys("symantec_web_gateway/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Variable Initialization
symPort = "";
symVer = "";

## get the port
if(!symPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!symVer = get_app_version(cpe:CPE, port:symPort)){
  exit(0);
}

##Check if version is less than 5.2.2
if(version_is_less(version:symVer, test_version:"5.2.2"))
{
  security_message(port:symPort);
  exit(0);
}
