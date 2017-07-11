###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantom_dos_vuln.nasl 6376 2017-06-20 10:00:24Z teissa $
#
# Foxit PhantomPDF Denial of Service Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805363");
  script_version("$Revision: 6376 $");
  script_cve_id("CVE-2015-2790");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-06-20 12:00:24 +0200 (Tue, 20 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-04-14 18:11:48 +0530 (Tue, 14 Apr 2015)");
  script_name("Foxit PhantomPDF Denial of Service Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Foxit PhantomPDF
  and is prone to Denial of Service Vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to Ubyte Size in a
  DataSubBlock structure or LZWMinimumCodeSize in a GIF image.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service attacks.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Foxit PhantomPDF version prior to
  7.1.");

  script_tag(name: "solution" , value:"Upgrade to Foxit PhantomPDF version
  7.1 or later, For updates refer to http://www.foxitsoftware.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1031877");
  script_xref(name : "URL" , value : "http://www.foxitsoftware.com/support/security_bulletins.php#FRD-24");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
  exit(-1);
}

## Grep for vulnerable version
if(version_is_less(version:foxitVer, test_version:"7.1.0.0"))
{
  report = 'Installed version: ' + foxitVer + '\n' +
           'Fixed version:     7.1'  + '\n';
  security_message(data:report);
  exit(0);
}
