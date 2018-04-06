###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_packagekit_format_string_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple Mac OS X PackageKit Format String Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to cause an unexpected
  application termination or arbitrary code execution.
  Impact Level: System";
tag_affected = "Mac OS X version 10.6 through 10.6.5
  Mac OS X Server version 10.6 through 10.6.5";
tag_insight = "The flaw is due to a format string error in PackageKit's handling of
  distribution scripts. A man-in-the-middle attacker may be able to cause an
  unexpected application termination or arbitrary code execution when Software
  Update checks for new updates.";
tag_solution = "Upgrade to Mac OS X/Server version 10.6.6 or later,
  For updates refer to http://support.apple.com/downloads/";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.6.6 Update.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902715");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-23 07:05:00 +0200 (Tue, 23 Aug 2011)");
  script_cve_id("CVE-2010-4013");
  script_bugtraq_id(45693);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apple Mac OS X PackageKit Format String Vulnerability");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4498");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42841");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024938");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Jan/msg00000.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
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
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.6.0", test_version2:"10.6.5"))
  {
    security_message(0);
    exit(0);
  }
}
