# OpenVAS Vulnerability Test
# $Id: kerio_mailserver_admin_port.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Kerio Mailserver Admin Service
#
# Authors:
# Javier Munoz Mellid <jm@udc.es>
#
# Copyright:
# Copyright (C) 2005 Javier Munoz Mellid
# Copyright (C) 2005 Secure Computer Group. University of A Coruna
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The administrative interface of a mail server is listening on
this port.

Description :

The remote host appears to be running the Kerio Admin MailServer
Admin Service on this port.";

tag_solution = "If this service is not needed, disable it or filter incoming traffic
to this port.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18184");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(13458);
 script_cve_id("CVE-2005-1062", "CVE-2005-1063");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 name = "Kerio Mailserver Admin Service";

 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

 script_copyright("This script is Copyright (C) 2005 Javier Munoz Mellid");
 script_family("Service detection");
 script_dependencies("find_service.nasl");

 script_require_ports(44337);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

function kms_isWeakAdminProtocol(port)
{

  soc = open_sock_tcp(port);

  if (!soc) return 0;

  vuln = 1;

  for(i=0;i<5;i=i+1) {

        s = raw_string(0x01);
        send(socket:soc, data: s);

        if (!soc) vuln = 0;

        r = recv(socket: soc, length: 16);

        if (isnull(r)||(strlen(r)!=2)||(ord(r[0])!=0x01)||(ord(r[1])!=0x00))
        {

                vuln = 0;
                break;

        }

  }

  close(soc);

  if (vuln)
        return 1;
  else
        return 0;
}

port = 44337;           # default kms port

if (! get_port_state(port)) exit(0);

if (kms_isWeakAdminProtocol(port)) security_message(port);

exit(0);
