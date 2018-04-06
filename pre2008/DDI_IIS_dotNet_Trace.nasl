# OpenVAS Vulnerability Test
# $Id: DDI_IIS_dotNet_Trace.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IIS ASP.NET Application Trace Enabled
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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

tag_summary = "The ASP.NET web application running in the root
directory of this web server has application
tracing enabled. This would allow an attacker to
view the last 50 web requests made to this server,
including sensitive information like Session ID values
and the physical path to the requested file.";

tag_solution = "Set <trace enabled=false> in web.config";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.10993");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"7.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
    name = "IIS ASP.NET Application Trace Enabled";
    script_name(name);


    summary = "Checks for ASP.NET application tracing";


    script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");

    script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");

    family = "Web application abuses";

    script_family(family);
    script_dependencies("secpod_ms_iis_detect.nasl");
    script_require_ports("Services/www", 80);
    script_mandatory_keys("IIS/installed");

    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);

    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if( ! get_kb_item("IIS/" + port + "/Ver" ) ) exit( 0 );

req = http_get(item:"/trace.axd", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ("Application Trace" >< res)
{
    security_message(port:port);
}
