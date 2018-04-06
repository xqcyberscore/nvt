###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nullftp_server_site_cmd_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Null FTP Server SITE Command Execution Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary codes
  in the context of the application.
  Impact Level: Application";
tag_affected = "NULL FTP Server Free and Pro version prior to 1.1.0.8 on Windows";
tag_insight = "An error is generated while handling custom SITE command containing shell
  metacharacters such as & (ampersand) as a part of an argument.";
tag_solution = "Upgrade to the latest version 1.1.0.8 or later
  http://www.vwsolutions.com/NullFTPServer/";
tag_summary = "This host has Null FTP Server installed and is prone to arbitrary
  code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800546");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6534");
  script_bugtraq_id(32656);
  script_name("Null FTP Server SITE Command Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32999");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7355");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47099");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_nullftp_server_detect.nasl");
  script_require_keys("NullFTP/Server/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

nullPort = get_kb_item("Services/ftp");
if(!nullPort){
  nullPort = 21;
}

if(get_port_state(nullPort))
{
  banner = get_ftp_banner(port:nullPort);
  if("Null FTP Server" >!< banner){
    exit(0);
  }

  ver = get_kb_item("NullFTP/Server/Ver");
  if(!ver){
    exit(0);
  }

  # Grep for version prior to 1.1.0.8
  if(version_is_less(version:ver, test_version:"1.1.0.8")){
    security_message(nullPort);
  }
}
