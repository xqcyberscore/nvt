###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netmri_detect.nasl 2836 2016-03-11 09:07:07Z benallard $
#
# NetMRI Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

tag_summary = "Detection of NetMRI.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103575";   

if (description)
{

 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_version ("$Revision: 2836 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:07:07 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-09-25 12:05:19 +0200 (Tue, 25 Sep 2012)");
 script_name("NetMRI Detection");
 script_summary("Checks for the presence of NetMRI");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:443);
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port, transport:get_port_transport(port));
if(!soc)exit(0);

host = get_host_name();

req = string("POST /netmri/config/userAdmin/login.tdf HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "Content-Length: 15\r\n",
             "\r\n",
             "mode=LOGIN-FORM\r\n");

send(socket:soc, data:req);
while(buf = recv(socket:soc, length:1024)) {
  data += buf;
}

close(soc);

c = 0;

if("<title>NetMRI Login" >< data || "<title>Network Automation Login" >< data)
{

  lines = split(data);

  foreach line(lines) {

    c++;

    vers = 'unknown';
    if("Version:" >< line) {

       version = eregmatch(pattern:"<td>([^<]+)</td>", string:lines[c]); 
       if(isnull(version[1]))exit(0);

       vers = version[1];

    }    

    set_kb_item(name: string("www/", port, "/netmri"), value: string(vers," under /"));
    set_kb_item(name:"netMRI/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:infoblox:netmri:");
    if(isnull(cpe))
      cpe = 'cpe:/a:infoblox:netmri';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"NetMRI", version:vers, install:"/", cpe:cpe, concluded: version[0]),
                port:port);

    exit(0);
  }  
}  

exit(0);
