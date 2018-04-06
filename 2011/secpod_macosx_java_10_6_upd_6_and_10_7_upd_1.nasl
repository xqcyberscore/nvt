###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_java_10_6_upd_6_and_10_7_upd_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Java for Mac OS X 10.6 Update 6 And 10.7 Update 1
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user.
  Impact Level: System/Application";
tag_affected = "Java for Mac OS X v10.6.6 and v10.7.2 or Mac OS X Server v10.6.8 and v10.7.2.";
tag_insight = "For more information on the vulnerabilities refer the below links.";
tag_solution = "Upgrade to Java for Mac OS X 10.6 Update 6 and 10.7 Update 1,
  For updates refer to http://support.apple.com/kb/HT5045";
tag_summary = "This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 6 and 10.7 Update 1.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902630");
  script_tag(name:"creation_date", value:"2011-11-17 11:36:14 +0100 (Thu, 17 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3545",
                "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549",
                "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554",
                "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560",
                "CVE-2011-3561");
  script_bugtraq_id(49388, 50215, 50218, 50220, 50239, 50243, 50211, 50223, 50224,
                    50248, 50246, 50216, 50231, 50234, 50242, 50236, 50250);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Java for Mac OS X 10.6 Update 6 And 10.7 Update 1");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5045");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4884");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4885");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/Security-announce//2011/Nov/msg00000.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
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

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    ## Check for the security update
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6", diff:"6"))
    {
      security_message(0);
      exit(0);
    }
  }

  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.7.2"))
  {
    ## Check for the security update
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.7", diff:"1")){
      security_message(0);
    }
  }
}
