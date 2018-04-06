###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_nov12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Apple Safari Multiple Vulnerabilities (APPLE-SA-2012-09-19-3)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow an attacker to bypass certain security
  restrictions and compromise a user's system.
  Impact Level: Application";
tag_affected = "Apple Safari versions prior to 6.0.2 Mac OS X";
tag_insight = "- A race condition error exists within the webkit component when handling
    JavaScript arrays and can be exploited to execute arbitrary code.
  - A use-after-free error exists in the handling of SVG images.";
tag_solution = "Upgrade to Apple Safari version 6.0.2 or later,
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "This host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802484");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-3748", "CVE-2012-5112");
  script_bugtraq_id(56362, 55867);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-11-02 15:21:30 +0530 (Fri, 02 Nov 2012)");
  script_name("Apple Safari Multiple Vulnerabilities (APPLE-SA-2012-09-19-3)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1222");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5568");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51157/");
  script_xref(name : "URL" , value : "http://prod.lists.apple.com/archives/security-announce/2012/Nov/msg00001.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_require_keys("AppleSafari/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

osName = "";
osVer = "";
safVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.7.5")||
     version_is_equal(version:osVer, test_version:"10.8.2"))
  {
    safVer = get_kb_item("AppleSafari/MacOSX/Version");
    if(!safVer){
      exit(0);
    }

    ## Grep for Apple Safari Versions prior to 6.0.2
    if(version_is_less(version:safVer, test_version:"6.0.2")){
      security_message(0);
    }
  }
}
