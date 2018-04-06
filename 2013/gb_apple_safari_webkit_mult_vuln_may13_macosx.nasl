###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_mult_vuln_may13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Apple Safari Webkit Multiple Vulnerabilities - May13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker cause memory corruption,
  arbitrary code execution or denial of service.
  Impact Level: System/Application";

tag_affected = "Apple Safari versions prior to 6.0.3 on Mac OS X";
tag_insight = "Multiple flaws due to unspecified memory corruption issues in WebKit.";
tag_solution = "Upgrade to Apple Safari version 6.0.3 or later,
  For updates refer to http://www.apple.com/support/downloads";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803379");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0960","CVE-2013-0961");
  script_bugtraq_id(58496, 58495);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-02 15:50:15 +0530 (Thu, 02 May 2013)");
  script_name("Apple Safari Webkit Multiple Vulnerabilities - May13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52658");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5671");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028292");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2013/Mar/msg00003.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
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

## Variable Initialization
osName = "";
osVer = "";
safVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit(0);
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

    ## Grep for Apple Safari Versions prior to 6.0.3
    if(version_is_less(version:safVer, test_version:"6.0.3"))
    {
      security_message(0);
      exit(0);
    }
  }
}
