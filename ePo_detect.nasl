###############################################################################
# OpenVAS Vulnerability Test
# $Id: ePo_detect.nasl 7268 2017-09-26 08:43:43Z cfischer $
#
# ePo Agent Detection
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

tag_summary = "Detection of ePo Agent
                    
The script sends a connection request to the server and attempts to
extract some information from the reply.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100329");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7268 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-26 10:43:43 +0200 (Tue, 26 Sep 2017) $");
 script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("ePo Agent Detection");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","http_version.nasl","netbios_name_get.nasl");
 script_require_ports("Services/www", 8081);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:8081);

 url = string("/");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

 if("Agent-ListenServer" >< buf && "displayResult()" >< buf) {

   domain = get_kb_item("SMB/name");

   if(!domain) {
     ip = get_host_ip();
     hostname = get_host_name();

     if(ip != hostname) {
       host = split(hostname,sep:".",keep:FALSE);
       if(!isnull(host[0]))domain = host[0];
     }  
   }

   if(domain) {
      url = '/Agent_' + domain + '.xml';
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    }  

 }  

 if(egrep(pattern:"Agent-ListenServer", string: buf, icase: TRUE) ||
   (egrep(pattern:"naLog>", string: buf, icase: FALSE) &&
    egrep(pattern:"ComputerName>", string: buf, icase: FALSE) &&
    egrep(pattern:"FrameworkLog", string: buf, icase: FALSE))) {

    info_head = string("\n\nInformation that was gathered from url '",url,"' on port ",port,".\n\n");

    if("403 Forbidden" >< buf) {
    
      info += string("Could not read remote log. Error: 403 Forbidden\n");

    } else {  

      if(lines = split(buf, sep:'><', keep: TRUE)) {
  
        foreach line (lines) { 
 
         if(computer_name = eregmatch(string: line, pattern:'ComputerName>([^<]+)</ComputerName>',icase:TRUE)) {
          if(!isnull(computer_name[1]))cn=computer_name[1];
         }	 
       
         if(version = eregmatch(string: line, pattern: "version>([^<]+)</version>",icase:TRUE)) {
           if(!isnull(version[1]))vers=version[1];
         }

         if(connected = eregmatch(string: line, pattern: 'Log component="[0-9]+" time="([^"]+)" type="3">(Agent is connecting to ePO server|Agent stellt Verbindung zu ePO-Server her)</Log>',icase:TRUE)) {
           if(!isnull(connected[1]))co=connected[1];
         }	

         if(repServer = eregmatch(string: line, pattern: 'Log component=[^>]+>Checking update packages from repository ([a-zA-Z0-9_-]+).</Log',icase:FALSE)) {
	   if(!isnull(repServer[1]))rserver = repServer[1];
         }	
	
         if(isnull(rserver)) {
          if(repServer = eregmatch(string:line, pattern: "ePOServerName>([^<]+)</ePOServerName>")) {
           if(!isnull(repServer[1]))rserver = repServer[1];  
          }   
         } 
      
       }  
     }
   
   }

    set_kb_item(name: string("www/", port, "/ePoAgent"), value: TRUE);
    register_service(port:port,  ipproto:"tcp", proto:"ePoAgent");

    if(!isnull(cn)) {
      info += string("ComputerName: ", cn, "\n");
    }  

    if(!isnull(vers)) {
      info += string("ClientVersion: ", vers, "\n");
    } 

    if(!isnull(rserver)) {
      info += string("Repository-Server: ", rserver, "\n");
    }  

    if(!isnull(co)) {
      info += string("Last connect to ePo-Server: ", co,"\n");
    }

    if(info) {
      extra = info_head + info;
    }

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:agent:");
    if(isnull(cpe))
            cpe = 'cpe:/a:mcafee:agent';

    register_product(cpe:cpe, location:port + "/tcp", port:port);

    log_message(data: build_detection_report(app:"ePo Agent", version:vers, install:port + '/tcp', cpe:cpe, port:port, concluded: version[0], extra:extra),
                port:port);
    exit(0);
 }

exit(0);
