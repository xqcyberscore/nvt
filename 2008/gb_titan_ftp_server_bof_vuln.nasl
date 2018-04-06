###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_titan_ftp_server_bof_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Titan FTP Server DELE Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to deny the service.";
tag_affected = "Titan FTP Server version 6.05 build 550 and prior.";
tag_insight = "The flaw exists in server due to improper handling of input passed to the
  command DELE.";
tag_solution = "Upgrade to the latest version,
  http://www.titanftp.com/download/index.html";
tag_summary = "This host is running Titan FTP Server and is prone to remote
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800073");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5281", "CVE-2008-0702", "CVE-2008-0725");
  script_bugtraq_id(27611);
  script_name("Titan FTP Server DELE Command Remote Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0802-exploits/titan-heap-py.txt");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28760");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("Titan FTP Server" >!< banner){
  exit(0);
}

ftpVer = eregmatch(pattern:"Titan FTP Server ([0-9.]+)", string:banner);
if(ftpVer[1] != NULL)
{
  # Grep for version <= 6.05.550
  if(version_is_less_equal(version:ftpVer[1], test_version:"6.05.550")){
    security_message(port);
  }
}
