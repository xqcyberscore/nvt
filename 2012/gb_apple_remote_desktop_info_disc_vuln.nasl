###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_remote_desktop_info_disc_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Apple Remote Desktop Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to gain sensitive information.
  Impact Level: Application";
tag_affected = "Apple Remote Desktop version 3.5.2";
tag_insight = "The flaw is due to an error in application, when connecting to a
  third-party VNC server with 'Encrypt all network data' set, data is not
  encrypted and no warning is produced.";
tag_solution = "Upgrade to Apple Remote Desktop version 3.5.3 or later,
  For updates refer to http://support.apple.com/downloads/";
tag_summary = "This host is installed with Apple Remote Desktop and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802964");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0681");
  script_bugtraq_id(55100);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-09-25 18:02:57 +0530 (Tue, 25 Sep 2012)");
  script_name("Apple Remote Desktop Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5462");
  script_xref(name : "URL" , value : "http://support.apple.com/downloads");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50352");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/Sep/msg00002.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

## Variable Initailization
sock = "";
rdVer = "";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if(!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the version of Apple Remote Desktop
rdVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /System/Library/" +
                 "CoreServices/RemoteManagement/ARDAgent.app/Contents/Info " +
                 "CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(rdVer) || "does not exist" >< rdVer){
  exit(0);
}

## Apple Remote Desktop version 3.5.2
if(version_is_equal(version:rdVer, test_version:"3.5.2")){
  security_message(0);
}
