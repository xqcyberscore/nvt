# OpenVAS Vulnerability Test
# $Id: qpopper_user_disclosure.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: QPopper Username Information Disclosure
#
# Authors:
# Scott Shebby scotts@scanalert.com
# based on Thomas Reinke's qpopper2.nasl
#
# Copyright:
# Copyright (C) 2004 Scott Shebby
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

tag_solution = "None at this time";

tag_summary = "The remote server appears to be running a version of QPopper 
that is older than 4.0.6.

Versions older than 4.0.6 are vulnerable to a bug where remote 
attackers can enumerate valid usernames based on server 
responses during the authentication process.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.12279");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(7110);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "QPopper Username Information Disclosure";
 script_name(name);


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");


 script_copyright("This script is Copyright (C) 2004 Scott Shebby");

 family = "General";

 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/pop3", 110);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner){
    if(get_port_state(port)){
        soc = open_sock_tcp(port);
        if(!soc)exit(0);
        banner = recv_line(socket:soc, length:4096);
    }
}

if(banner){
    if(ereg(pattern:".*Qpopper.*version ([0-3]\.*|4\.0\.[0-5][^0-9]).*", string:banner, icase:TRUE)){
        security_message(port);
    }
}
