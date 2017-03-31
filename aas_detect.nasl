###############################################################################
# OpenVAS Vulnerability Test
# $Id: aas_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# A A S Application Access Server Detection
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

tag_summary = "The A A S Application Access Server is running at this port. The A A S
  Application Access Server makes the PC administration possible
  over LAN and WANs.";

if (description)
{
 script_id(100196);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("A A S Application Access Server  Server Detection");  

 script_summary("Checks for the presence of A A S Application Access Server ");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 6262);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.klinzmann.name/a-a-s/index_en.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100196";
SCRIPT_DESC = "A A S Application Access Server  Server Detection";

port = get_http_port(default:6262);

if(!get_port_state(port))exit(0);

 url = string("/"); 
 req = http_get(item:url, port:port);
 buf = http_send_recv(port:port, data:req, bodyonly:FALSE);  

 if( buf == NULL )exit(0);
 if( egrep(pattern: 'Server: AAS', string: buf, icase: TRUE) )
 { 
   
    vers = string("unknown");

    ### try to get version.
    version = eregmatch(string: buf, pattern: 'Server: AAS/([0-9.]+)',icase:TRUE);
    
    if ( !isnull(version[1]) ) {
       vers=version[1];
    } 

    set_kb_item(name: string("www/", port, "/aas"), value: vers);	
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:klinzmann:application_access_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("\n\nA A S Application Access Server Version '");
    info += string(vers);
    info += string("' was detected on the remote host\n");

       if(report_verbosity > 0) {
         log_message(port:port,data:string(info));
         exit(0);
       }	 
  
 }

exit(0);
