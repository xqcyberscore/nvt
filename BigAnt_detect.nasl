###############################################################################
# OpenVAS Vulnerability Test
# $Id: BigAnt_detect.nasl 9996 2018-05-29 07:18:44Z cfischer $
#
# BigAnt IM Server Detection
#
# Authors:
# Michael Meyer
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100280");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9996 $");
 script_tag(name:"last_modification", value:"$Date: 2018-05-29 09:18:44 +0200 (Tue, 29 May 2018) $");
 script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("BigAnt IM Server Detection");

 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("AntServer/banner");
 script_require_ports("Services/www", 6660);
 script_tag(name : "summary" , value : "This host is running BigAnt IM Server, a instant messaging solution
for enterprise.");
 script_xref(name : "URL" , value : "http://www.bigantsoft.com/");
 exit(0);
}

include("http_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:6660);
banner = get_http_banner(port: port);
if(!banner)exit(0);

if(egrep(pattern:"AntServer", string:banner)) {
  register_service(port:port, ipproto:"tcp", proto:"BigAnt");
  log_message(port:port);
}

exit(0);
