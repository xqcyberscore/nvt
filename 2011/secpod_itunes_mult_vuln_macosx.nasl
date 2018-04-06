###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_itunes_mult_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple iTunes Multiple Vulnerabilities (Mac OS X)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code on
  the target user's system.
  Impact Level: System/Application";
tag_affected = "Apple iTunes version prior to 10.2 on Mac OS X version 10.5";
tag_insight = "The flaws are due to the error while handling the crafted files.";
tag_solution = "Upgrade to Apple iTunes version 10.2 or later
  For updates refer to http://www.apple.com/itunes/download/";
tag_summary = "This host has installed apple iTunes and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902718");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2010-1205", "CVE-2010-2249", "CVE-2011-0170");
  script_bugtraq_id(41174);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple iTunes Multiple Vulnerabilities (Mac OS X)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4554");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025152");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Mar/msg00000.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_require_keys("Apple/iTunes/MacOSX/Version");
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

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check the affected OS versions
if(osVer =~ "^10.5\.*")
{
  ## Get Apple iTunes version from KB
  itunesVer = get_kb_item("Apple/iTunes/MacOSX/Version");
  if(itunesVer)
  {
    ## Check for Apple iTunes versions < 10.2
    if(version_is_less(version:itunesVer, test_version:"10.2"))
    {
      security_message(0);
      exit(0);
    }
  }
}
