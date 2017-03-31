###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_norton_internet_security_sym16_010.nasl 5557 2017-03-13 10:00:29Z teissa $
#
# Symantec Norton Internet Security Decomposer Engine Multiple Parsing Vulnerabilities
# 
# Authors:
# Tushar Khelge <tushar.khelge@secpod.com>
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

CPE = "cpe:/a:symantec:norton_internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808512");
  script_version("$Revision: 5557 $");
  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646");
  script_bugtraq_id(91434, 91436, 91437, 91438, 91431, 91439, 91435);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-13 11:00:29 +0100 (Mon, 13 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-07-04 16:11:01 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Norton Internet Security Decomposer Engine Multiple Parsing Vulnerabilities");

  script_tag(name: "summary" , value: "This host is installed with Symantec
  Norton Internet Security and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Multiple flaws are due to an error in
  Parsing of maliciously-formatted container files in Symantecs Decomposer engine.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Symantec Norton Internet Security NGC 22.7 and prior.");

  script_tag(name: "solution" , value:"Update Symantec Norton Internet Security
  through LiveUpdate.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Norton/InetSec/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
sepVer= "";

## Get version
if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

##https://community.norton.com/en/comment/7056501#comment-7056501
if(version_is_less(version:sepVer, test_version:"22.7.0.76"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"22.7.0.76");
  security_message(data:report);
  exit(0);
}

