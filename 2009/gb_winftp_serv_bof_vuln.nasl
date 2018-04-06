###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winftp_serv_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# WinFTP Server LIST Command Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Allows remote authenticated attackers to execute arbitrary code within the
  context of the affected application resulting in buffer overflow and can cause
  denial of service condition.
  Impact Level: Application";
tag_affected = "WinFTP Server version 2.3.0 and prior on Windows.";
tag_insight = "The flaw exists when processing malformed arguments passed to the LIST command
  with an asterisk (*) character.";
tag_solution = "Upgrade to WinFTP Server version 3.5.0 or later
  For updates refer to http://www.wftpserver.com/";
tag_summary = "This host is running WinFTP Server and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800346");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0351");
  script_bugtraq_id(33454);
  script_name("WinFTP Server LIST Command Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7875");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48263");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_winftp_serv_detect.nasl");
  script_require_keys("WinFTP/Server/Ver");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  exit(0);
}

winFtpVer = get_kb_item("WinFTP/Server/Ver");
if(!winFtpVer){
  exit(0);
}

# Check for version 2.3.0.0 and prior
if(version_is_less_equal(version:winFtpVer, test_version:"2.3.0.0")){
  security_message(ftpPort);
}
