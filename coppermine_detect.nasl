###############################################################################
# OpenVAS Vulnerability Test
# $Id: coppermine_detect.nasl 5720 2017-03-24 14:15:57Z cfi $
#
# Coppermine Detection
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

tag_summary = "This host is running Coppermine, a web picture gallery script
  written in PHP using GD or ImageMagick as image library with a MySQL
  backend.";

if (description)
{
 script_id(100174);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5720 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-24 15:15:57 +0100 (Fri, 24 Mar 2017) $");
 script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Coppermine Detection");  
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://coppermine-gallery.net/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100174";
SCRIPT_DESC = "Coppermine Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/coppermine", "/gallery", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL )continue;
 
 if(
    egrep(pattern: 'Powered by <a [^>]+Coppermine Photo Gallery', string: buf, icase: TRUE) &&
    egrep(pattern: 'Set-Cookie: (coppermine_data.*|cpg.*)', string: buf, icase: TRUE))
 { 
    
    vers = string("unknown");

    ### try to get version.
    version = eregmatch(string: buf, pattern: 'Coppermine Photo Gallery ([0-9.]+)',icase:TRUE);
    
    if ( !isnull(version[1]) ) {
       vers=version[1];
    } else {

     version = eregmatch(string: buf, pattern: 'Coppermine version: ([0-9.]+)',icase:TRUE);

     if ( !isnull(version[1]) ) {
       vers=version[1];
     } else {
      
       url = string(dir, "/docs/showdoc.php");
       req = http_get(item:url, port:port);
       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

       version = eregmatch(string: buf, pattern: 'Coppermine Photo Gallery v([0-9.]+)',icase:TRUE);

       if ( !isnull(version[1]) ) {
         vers=version[1];
       } else {
   
	 url = string(dir, "/CHANGELOG");
	 req = http_get(item:url, port:port);
	 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

	 version = eregmatch(string: buf, pattern: 'Release of cpg([0-9.]+)',icase:TRUE);

	 if ( !isnull(version[1]) ) {
          vers=version[1];
	 }  
       }  
     }  
   }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/coppermine"), value:tmp_version);
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:coppermine:coppermine_photo_gallery:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("\n\nCoppermine Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n"); 

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
