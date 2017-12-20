###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_mult_memory_corruption_vuln_win.nasl 8173 2017-12-19 11:45:56Z cfischer $
#
# ImageMagick Multiple Memory Corruption Vulnerabilities (Windows)
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810562");
  script_version("$Revision: 8173 $");
  script_cve_id("CVE-2016-8862", "CVE-2016-8866");
  script_bugtraq_id(93794);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 12:45:56 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-02-21 10:39:33 +0530 (Tue, 21 Feb 2017)");
  script_name("ImageMagick Multiple Memory Corruption Vulnerabilities (Windows)");

  script_tag(name: "summary" , value:"This host is installed with ImageMagick
  and is prone to multiple memory corruption vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to
  a memory corruption error in 'AcquireMagickMemory' function  in 
  MagickCore/memory.c script.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote 
  attackers to cause some unspecified impacts.

  Impact Level: Application");

  script_tag(name: "affected" , value:"ImageMagick version before 7.0.3.8 on 
  Windows");

  script_tag(name: "solution" , value: "Upgrade to ImageMagick version 7.0.3.8
  or later. For updates refer to http://www.graphicsmagick.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://blogs.gentoo.org/ago/2016/10/17/imagemagick-memory-allocation-failure-in-acquiremagickmemory-memory-c");
  script_xref(name : "URL" , value : "https://blogs.gentoo.org/ago/2016/10/20/imagemagick-memory-allocation-failure-in-acquiremagickmemory-memory-c-incomplete-fix-for-cve-2016-8862");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2016/10/20/3");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
gmVer = "";

## Get the version
if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for the vulnerable version 
## CVE-2016-8866 is due to an incomplete fix for CVE-2016-8862
## CVE-2016-8862 , not fixed completly in 7.0.3.3, complete fix is in 7.0.3.8
if(version_is_less(version:gmVer, test_version:"7.0.3.8"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"7.0.3.8");
  security_message(data:report);
  exit(0);
}
