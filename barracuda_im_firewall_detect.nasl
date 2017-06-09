###############################################################################
# OpenVAS Vulnerability Test
# $Id: barracuda_im_firewall_detect.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Barracuda IM Firewall Detection
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

tag_summary = "This host is running Barracuda IM Firewall. Barracuda IM Firewall
control and manage internal and external instant messaging (IM)
traffic.";

if (description)
{
 script_id(100392);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6065 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
 script_tag(name:"creation_date", value:"2009-12-11 12:55:06 +0100 (Fri, 11 Dec 2009)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("Barracuda IM Firewall Detection");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("BarracudaHTTP/banner");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.barracudanetworks.com/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100392";
SCRIPT_DESC = "Barracuda IM Firewall Detection";

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if("Server: BarracudaHTTP" >!< banner)exit(0);

 url = string(dir, "/cgi-mod/index.cgi");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "<title>Barracuda IM Firewall", string: buf, icase: TRUE)) {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "barracuda.css\?v=([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/barracuda_im_firewall"), value: vers);
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/h:barracuda_networks:barracuda_im_firewall:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("\n\nBarracuda IM Firewall Version '");
    info += string(vers);
    info += string("' was detected on the remote host.\n");

       if(report_verbosity > 0) {
         log_message(port:port,data:info);
       }
       exit(0);

 }

exit(0);

