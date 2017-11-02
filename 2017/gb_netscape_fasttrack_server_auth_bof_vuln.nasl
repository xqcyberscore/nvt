###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netscape_fasttrack_server_auth_bof_vuln.nasl 7610 2017-11-01 13:14:39Z jschulte $
#
# Netscape FastTrack Server Authentication Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:netscape:fasttrack_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811546");
  script_version("$Revision: 7610 $");
  script_cve_id("CVE-1999-0853");
  script_bugtraq_id(847);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-01 14:14:39 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-07-28 15:05:05 +0530 (Fri, 28 Jul 2017)");
  script_name("Netscape FastTrack Server Authentication Buffer Overflow Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with Netscape FastTrack Server
  and is prone to buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an error in the
  HTTP Basic Authentication procedure for the servers, which has a buffer overflow
  condition when a long username or password (over 508 characters) are provided.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to gain root privileges under UNIX and SYSTEM privileges under NT.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Netscape FastTrack Server 3.01");

  script_tag(name: "solution" , value:"No solution or patch is available as of
  1st November, 2017. The product is end-of-life and the vulnerability was disclose in 1999.
  A fix is unlikely.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://cve.circl.lu/cve/CVE-1999-0853");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_netscape_fasttrack_server_detect.nasl");
  script_mandatory_keys("Netscape/FastTrack/Server/version");
  exit(0);
}


# Code starts from here

include("host_details.inc");
include("version_func.inc");

# Variable Initialization
netVer = "";
netport = 0;

## Get port
if (!netport = get_app_port(cpe: CPE)){
  exit(0);
}

## Get version
if(!netVer = get_app_version(cpe:CPE, port:netport)){
  exit(0);
}

## Check for vulnerable versions
if(netVer == "3.01")
{
  report = report_fixed_ver(installed_version:netVer, fixed_version:"NoneAvailable");
  security_message(data:report, port:netport);
  exit(0);
}
