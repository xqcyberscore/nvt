###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sopcast_uri_handling_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# SopCast 'sop://' URI Handling Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary code in the context of the user running an affected application. Failed
exploit attempts may lead to a denial-of-service condition.

Impact Level: System/Application";

tag_affected = "SopCast version 3.4.7.45585";

tag_insight = "The flaw is due to a boundary error in the WebPlayer ActiveX
Control when handling the 'ChannelName' property can be exploited to cause a
stack based buffer overflow via a specially crafted 'sop://' URL string.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with SopCast and is prone to buffer overflow
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802281");
  script_version("$Revision: 9351 $");
  script_bugtraq_id(50901);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-08 15:15:15 +0530 (Thu, 08 Dec 2011)");
  script_name("SopCast 'sop://' URI Handling Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40940");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18200");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107528/ZSL-2011-5063.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5063.php");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm SopCast
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SopCast";
if(!registry_key_exists(key:key)){
  exit(0);
}

sopName = registry_get_sz(key:key, item:"DisplayName");
if("SopCast" >< sopName)
{
  ## Get Installation Path
  sopPath = registry_get_sz(key:key, item:"DisplayIcon");
  if(!sopPath){
    exit(0);
  }
  sopPath = sopPath - "\SopCast.exe";

  ## Get Version from sopocx.ocx
  sopVer = fetch_file_version(sysPath:sopPath, file_name:"sopocx.ocx");
  if(! sopVer){
   exit(0);
  }

  ## Check for SopCast version 3.4.7.45585
  if(version_is_equal(version:sopVer, test_version:"3.4.7.45585")) {
    security_message(0);
  }
}
