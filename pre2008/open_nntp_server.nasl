# OpenVAS Vulnerability Test
# $Id: open_nntp_server.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Open News server
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

tag_solution = "Enforce authentication or filter connections from outside";

tag_summary = "The remote server seems open to outsiders.
Some people love open public NNTP servers to
be able to read and/or post articles anonymously.
Keep in mind that robots are harvesting such 
open servers on Internet, so you cannot hope that
you will stay hidden for long.

Unwanted connections could waste your bandwidth
or put you into legal trouble if outsiders use your server
to read and/or post 'politically incorrects' articles.

** As it is very common to have IP based authentication,
** this might be a false positive if the OpenVAS scanner is
** among the allowed source addresses.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.17204");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 name = "Open News server";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "General";
 script_family(family);

 script_dependencies("nntp_info.nasl");
 script_require_ports("Services/nntp", 119);

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 exit(0);
}

# Unusable server
if (! get_kb_item('nntp/'+port+'/ready') ||
    ! get_kb_item('nntp/'+port+'/noauth') )
 exit(0);

post = get_kb_item('nntp/'+port+'/posting');
# If we want to avoid FP, check that the message was posted
if (post && get_kb_item('nntp/'+port+'/posted') <= 0)
  post = 0;

if (! post) 
  security_message(port: port, data: "Post is not affected");
else
  security_message(port: port, data: "Post is affected");
