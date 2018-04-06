###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_sandbox_profiles_sec_bypass_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Apple Mac OS X Predefined Sandbox Profiles Security Bypass Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to gain unauthorized
access to restricted network resources through the use of Apple events.

Impact Level: Application";

tag_affected = "Apple Mac OS X version 10.5.x through 10.7.2";

tag_insight = "The kSBXProfileNoNetwork and kSBXProfileNoInternet sandbox
profiles fails to propagate restrictions to all created processes, which
allows remote attackers to access network resources via apple events to
invoke the execution of other applications not directly restricted by
the sandbox.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Apple Mac OS X operating system and
 is prone to sandbox profiles security bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803223");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2011-1516", "CVE-2008-7303");
  script_bugtraq_id(50644, 50716);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-01 12:42:10 +0530 (Fri, 01 Feb 2013)");
  script_name("Apple Mac OS X Predefined Sandbox Profiles Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48980");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71284");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/apple-osx-sandbox-bypass");

  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");
include("pkg-lib-macosx.inc");

## Variable Initialization
osName = "";
osVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

## Check the affected OS versions
if(version_in_range(version: osVer, test_version:"10.5.0", test_version2:"10.7.2")){
   security_message(0);
}
