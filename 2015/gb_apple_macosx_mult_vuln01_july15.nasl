###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_july15.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Apple Mac OS X Multiple Vulnerabilities-01 July15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805676");
  script_version("$Revision: 5351 $");
  script_cve_id("CVE-2015-3720", "CVE-2015-3718", "CVE-2015-3716", "CVE-2015-3715",
                "CVE-2015-3714", "CVE-2015-3713", "CVE-2015-3712", "CVE-2015-3711",
                "CVE-2015-3709", "CVE-2015-3708", "CVE-2015-3707", "CVE-2015-3706",
                "CVE-2015-3705", "CVE-2015-3704", "CVE-2015-3702", "CVE-2015-3701",
                "CVE-2015-3700", "CVE-2015-3699", "CVE-2015-3698", "CVE-2015-3697",
                "CVE-2015-3696", "CVE-2015-3695", "CVE-2015-3693", "CVE-2015-3692",
                "CVE-2015-3691", "CVE-2015-3694", "CVE-2015-3689", "CVE-2015-3688",
                "CVE-2015-3687", "CVE-2015-3721", "CVE-2015-3719", "CVE-2015-3717",
                "CVE-2015-3710", "CVE-2015-3703", "CVE-2015-3690", "CVE-2015-3686",
                "CVE-2015-3685", "CVE-2015-3684", "CVE-2015-3683", "CVE-2015-3682",
                "CVE-2015-3681", "CVE-2015-3680", "CVE-2015-3679", "CVE-2015-3678",
                "CVE-2015-3677", "CVE-2015-3676", "CVE-2015-3675", "CVE-2015-3674",
                "CVE-2015-3673", "CVE-2015-3672", "CVE-2015-3671");
  script_bugtraq_id(75493, 75495, 75491);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2015-07-10 12:16:49 +0530 (Fri, 10 Jul 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 July15");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service, write to
  arbitrary files,  execute arbitrary code with system privilege.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple Mac OS X versions before 10.10.4");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.10.4 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT204942");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2015/Jun/msg00002.html");
  script_summary("Check for the vulnerable version of Apple Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
osName = "";
osVer = "";

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

## Check for the Mac OS X
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_is_less(version:osVer, test_version:"10.10.4"))
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version: 10.10.4\n';
    security_message(data:report);
    exit(0);
  }
}
