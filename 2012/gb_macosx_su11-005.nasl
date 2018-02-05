###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su11-005.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Mac OS X Certificate Trust Policy Information Disclosure Vulnerability (2011-005)
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

tag_impact = "Successful exploitation could allow attackers to gain sensitive information.
  Impact Level: System";
tag_affected = "Certificate Trust Policy";
tag_insight = "The fraudulent certificates were issued by multiple certificate authorities
  operated by DigiNotar.";
tag_solution = "Run Mac Updates and update the Security Update 2011-005,
  For updates refer to http://support.apple.com/kb/DL1446";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2011-005.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802798");
  script_version("$Revision: 8649 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-06-26 18:25:17 +0530 (Tue, 26 Jun 2012)");
  script_name("Mac OS X Certificate Trust Policy Information Disclosure Vulnerability (2011-005)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4920");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/DL1446");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2011/Sep/msg00000.html");

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


include("version_func.inc");
include("pkg-lib-macosx.inc");

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
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    ## Check for the security update 2011.005
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2011.005")){
      security_message(0);
    }
  }
}
