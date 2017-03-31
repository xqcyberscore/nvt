# OpenVAS Vulnerability Test
# $Id: enterasys_dragon_reporting_detect.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Enterasys Dragon Enterprise Reporting detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host is running the Enterasys Dragon Enterprise Reporting on
this port.";

if(description)
{
 script_id(18532);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 
 name = "Enterasys Dragon Enterprise Reporting detection";

 script_name(name);
 

 
 summary = "Checks for Enterasys Dragon Enterprise Reporting console";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 
 family = "Service detection";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports(9443);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = 9443;

if(get_port_state(port))
{
  req1 = http_get(item:"/dragon/login.jsp", port:port);
  req = http_send_recv(data:req1, port:port);

  if(">Dragon Enterprise Reporting<" >< req)
  {
    log_message(port);
  }
}
