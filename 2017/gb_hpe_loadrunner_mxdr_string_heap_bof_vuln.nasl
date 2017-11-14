###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_loadrunner_mxdr_string_heap_bof_vuln.nasl 7689 2017-11-08 05:46:44Z teissa $
#
# HPE LoadRunner 'libxdrutil.dll mxdr_string method' RCE Vulnerability
# 
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811014");
  script_version("$Revision: 7689 $");
  script_cve_id("CVE-2017-5789");
  script_bugtraq_id(96774);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 06:46:44 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-04-25 17:17:50 +0530 (Tue, 25 Apr 2017)");
  script_name("HPE LoadRunner 'libxdrutil.dll mxdr_string method' RCE Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE LoadRunner
  and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The specific flaw exists within the
  'libxdrutil.dll mxdr_string method' from the lack of proper validation of the
  length of user-supplied data prior to copying it to a heap-based buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code under the context of the current process.

  Impact Level: System/Application.");

  script_tag(name:"affected", value:"HPE LoadRunner versions before 12.53
  patch 4.");

  script_tag(name:"solution", value:"Upgrade to HPE LoadRunner 12.53 Patch 4 or
  later. For updates refer to https://www.hpe.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-17-160");
  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03712en_us");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
hpVer= "";

## Get version
if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check For Version 12.53 and prior
## no version change after applying patch
## qod is reduced
## 12.53 == 12.53.1203.0
if(version_is_less_equal(version:hpVer, test_version:"12.53.1203.0"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"12.53 Patch 4");
  security_message(data:report);
  exit(0);
}
