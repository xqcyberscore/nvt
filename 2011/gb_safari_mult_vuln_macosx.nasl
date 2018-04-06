###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_safari_mult_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple MAC OS X v10.6.8 Safari Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to opening a maliciously
  crafted files, which leads to an unexpected application termination or
  arbitrary code execution.
  Impact Level: System/Application";
tag_affected = "Safari version prior to 5.1.1 on MAC OS X/Mac OS X Server 10.6.8";
tag_insight = "The flaws are due to
  - A directory traversal issue existed in the handling of safari-extension://
    URLs.
  - A policy issue existed in the handling of file:// URLs.
  - An uninitialized memory access issue existed in the handling of SSL
    certificates.
  - Multiple memory corruption issues existed in WebKit.
  - A cross-origin issue existed in the handling of the beforeload event,
    window.open method, document.documentURI property and inactive DOM windows
    in webkit.
  - A logic issue existed in the handling of cookies in Private Browsing mode.";
tag_solution = "Upgrade to Safari version 5.1.1 on later
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "This host is installed with Safari and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802192");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2011-3229", "CVE-2011-3230", "CVE-2011-3231", "CVE-2011-1440",
                "CVE-2011-2338", "CVE-2011-2339", "CVE-2011-2341", "CVE-2011-2351",
                "CVE-2011-2352", "CVE-2011-2354", "CVE-2011-2356", "CVE-2011-2359",
                "CVE-2011-2788", "CVE-2011-2790", "CVE-2011-2792", "CVE-2011-2797",
                "CVE-2011-2799", "CVE-2011-2809", "CVE-2011-2811", "CVE-2011-2813",
                "CVE-2011-2814", "CVE-2011-2815", "CVE-2011-2816", "CVE-2011-2817",
                "CVE-2011-2818", "CVE-2011-2820", "CVE-2011-2823", "CVE-2011-2827",
                "CVE-2011-2831", "CVE-2011-2832", "CVE-2011-2833", "CVE-2011-2834",
                "CVE-2011-3235", "CVE-2011-3236", "CVE-2011-3237", "CVE-2011-3238",
                "CVE-2011-3239", "CVE-2011-3241", "CVE-2011-2800", "CVE-2011-2805",
                "CVE-2011-2819", "CVE-2011-3243", "CVE-2011-3242");
  script_bugtraq_id(50163, 50162, 50169, 47604, 50066, 51032, 48479, 48960, 49279,
                    49850, 49658, 50088, 50180);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple MAC OS X v10.6.8 Safari Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5000");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/Security-announce//2011/Oct/msg00004.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("macosx_safari_detect.nasl");
  script_require_ports("Services/ssh", 22);
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

## Check for the Mac OS X
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS version
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    safVer = get_kb_item("AppleSafari/MacOSX/Version");
    if(safVer)
    {
      if(version_is_less(version:safVer, test_version:"5.1.1")){
        security_message(0);
      }
    }
  }
}
