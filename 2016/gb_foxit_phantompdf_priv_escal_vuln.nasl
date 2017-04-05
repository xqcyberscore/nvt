###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantompdf_priv_escal_vuln.nasl 5612 2017-03-20 10:00:41Z teissa $
#
# Foxit PhantomPDF Local Privilege Escalation Vulnerability
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807561");
  script_version("$Revision: 5612 $");
  script_cve_id("CVE-2015-8843");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 11:00:41 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-25 16:44:43 +0530 (Mon, 25 Apr 2016)");
  script_name("Foxit PhantomPDF Local Privilege Escalation Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Foxit PhantomPDF
  and is prone to privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an error in 
  FoxitCloudUpdateService service which can trigger a memory corruption condition 
  by writing certain data to a shared memory region.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers 
  to execute code under the context of system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Foxit PhantomPDF version 7.2.0.722 
  and earlier.");

  script_tag(name: "solution" , value:"Upgrade to Foxit PhantomPDF version
  7.2.2 or later, For updates refer to http://www.foxitsoftware.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value:"http://www.zerodayinitiative.com/advisories/ZDI-15-640");
  script_xref(name : "URL" , value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("Foxit/PhantomPDF/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
foxitVer = "";

## Get version
if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
## Foxit PhantomPDF version 7.2.2 = 7.2.2.929
if(version_is_less_equal(version:foxitVer, test_version:"7.2.0.722"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"7.2.2.929");
  security_message(data:report);
  exit(0);
}
