# OpenVAS Vulnerability Test
# $Id: wsus_detect.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Windows Server Update Services detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Changes by Tenable Network Security :
# - "Services/www" check
# - Family changed to "Service detection"
# - Request fixed
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

tag_summary = "The remote host appears to be running Windows Server Update
Services.

Description:

This product is used to deploy easily and quickly latest 
Microsoft product updates.";

if(description)
{
 script_id(20377);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 name = "Windows Server Update Services detection";
 script_name(name);
 

 
 summary = "Checks for WSUS console";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 
 family = "Service detection";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80, 8530);
 script_xref(name : "URL" , value : "http://www.microsoft.com/windowsserversystem/updateservices/default.mspx");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

ports = get_kb_list ("Services/www");

if (isnull(ports))
  ports = make_list (8530);
else
  ports = make_list (8530, ports);


foreach port (ports)
{
 if(get_port_state(port))
 {
  req = http_get(item:"/Wsusadmin/Errors/BrowserSettings.aspx", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL )exit(0);

  if ( egrep (pattern:'<title>Windows Server Update Services error</title>.*href="/WsusAdmin/Common/Common.css"', string:r) ||
       egrep (pattern:'<div class="CurrentNavigation">Windows Server Update Services error</div>', string:r) )
  {
   log_message(port);
  }
 }
}

