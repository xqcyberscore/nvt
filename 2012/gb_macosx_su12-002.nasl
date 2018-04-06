###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su12-002.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mac OS X Multiple Vulnerabilities (2012-002)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Login Window,
  Bluetooth,
  curl,
  Directory Service,
  HFS,
  ImageIO,
  Kernel,
  libarchive,
  libsecurity,
  libxml,
  LoginUIFramework,
  PHP,
  Quartz Composer,
  QuickTime,
  Ruby,
  Samba,
  Security Framework,
  Time Machine,
  X11.";
tag_insight = "For more information on the vulnerabilities refer to the links below.";
tag_solution = "Upgrade to Mac OS X 10.7.4 or
  Run Mac Updates and update the Security Update 2012-002
  For updates refer to http://support.apple.com/kb/HT5281";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2012-002.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802794");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3389", "CVE-2012-0651", "CVE-2011-0241", "CVE-2011-2692",
                "CVE-2011-1167", "CVE-2011-1777", "CVE-2011-1778", "CVE-2012-0654",
                "CVE-2012-0655", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834",
                "CVE-2011-3919", "CVE-2012-0657", "CVE-2012-0658", "CVE-2012-0659",
                "CVE-2012-0660", "CVE-2011-1004", "CVE-2011-1005", "CVE-2011-4815",
                "CVE-2012-0870", "CVE-2012-1182", "CVE-2012-0662", "CVE-2012-0652",
                "CVE-2012-0649", "CVE-2012-0036", "CVE-2012-0642", "CVE-2011-3212",
                "CVE-2012-0656", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0830",
                "CVE-2012-0661", "CVE-2012-0675", "CVE-2011-2895", "CVE-2011-3328");
  script_bugtraq_id(49778, 49388, 53458, 48833, 48618, 46951, 47737, 53471,
                    53462, 48056, 49279, 49658, 51300, 53473, 53465, 53467,
                    53469, 46460, 46458, 51198, 52103, 52973, 53468, 53457,
                    53456, 51665, 52364, 50109, 53459, 50907, 51193, 51830,
                    53466, 53470, 49124, 49744);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-18 12:26:01 +0530 (Fri, 18 May 2012)");
  script_name("Mac OS X Multiple Vulnerabilities (2012-002)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1222");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5281");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/May/msg00001.html");
  script_xref(name : "URL" , value : "http://prod.lists.apple.com/archives/security-announce/2012/May/msg00001.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("pkg-lib-macosx.inc");
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

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    ## Check for the security update 2012.002
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2012.002"))
    {
      security_message(0);
      exit(0);
    }
  }

  ## Check if OS is 10.7 through 10.7.3
  if(version_in_range(version:osVer, test_version:"10.7", test_version2:"10.7.3")){
    security_message(0);
  }
}
