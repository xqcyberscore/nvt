###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_java_10_5_upd_9.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Java for Mac OS X 10.5 Update 9
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_affected = "Java for Mac OS X v10.5.8 and Mac OS X Server v10.5.8";
tag_insight = "For more information on the vulnerabilities refer the below links.";
tag_solution = "Upgrade to Java for Mac OS X 10.5 Update 9,
  For updates refer to http://support.apple.com/kb/HT4563";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.5 Update 9.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902556");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450",
                "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465",
                "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470",
                "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4476");
  script_bugtraq_id(46091, 46386, 46387, 46391, 46393, 46394, 46395, 46397,
                    46398, 46399, 46400, 46402, 46403, 46404, 46406, 46409);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Java for Mac OS X 10.5 Update 9");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4563");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Mar/msg00002.html");

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

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.5.8"))
  {
    ## Check for the security update
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.5Update", diff:"9"))
    {
      security_message(0);
      exit(0);
    }
  }
}
