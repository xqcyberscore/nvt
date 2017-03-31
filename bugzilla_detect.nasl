###############################################################################
# OpenVAS Vulnerability Test
# $Id: bugzilla_detect.nasl 3785 2016-08-02 10:07:03Z ckuerste $
#
# Bugzilla Detection
#
# Authors:
# Michael Meyer
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-07-26
# -modified to detect the rc part of the versions
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

tag_summary = "Detection of Bugzilla.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100093";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3785 $");
  script_tag(name:"last_modification", value:"$Date: 2016-08-02 12:07:03 +0200 (Tue, 02 Aug 2016) $");
  script_tag(name:"creation_date", value:"2009-03-31 18:59:35 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Bugzilla Detection");

  script_summary("Checks for the presence of Bugzilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");


## start script
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

dirs = make_list_unique("/bugzilla","/bugs",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.cgi");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "Bugzilla_login", string: buf) && egrep(pattern: "Bugzilla_password", string: buf) )
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");

    ### try to get version

    version = eregmatch(string: buf, pattern: "version ([0-9.]+)(.?rc([0-9]+)?)?",icase:TRUE);
    if (!isnull(version[1]) )
    {
      if(!isnull(version[2])){
        vers=version[1] + "." + version[2];
      }
    }

    if(isnull(version[1]))
    {
      url = string(dir, "/docs/en/txt/Bugzilla-Guide.txt");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      version = eregmatch(string: buf, pattern: "The Bugzilla Guide - ([0-9.]+)(.?rc([0-9]+)?)? Release");

      if ( !isnull(version[1]) )
      {
        if(!isnull(version[2])){
           vers=version[1] + "." + version[2];
        }
      }
      else
     {

       url = string(dir, "/CVS/Tag");
       req = http_get(item:url, port:port);
       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

       if( !isnull(buf))
       {
         version = eregmatch(string: buf, pattern: "BUGZILLA-([0-9._]+)(.?rc([0-9]+)?)? Release");
         if ( !isnull(version[1]) )
         {
           if(version[1] = ereg_replace(pattern:"_", string:version[1], replace:"."))
           {
             if ( !isnull(version[2]) ){
               vers=version[1] + "." + version[2];
             }
           }
         }
       }
     }
   }else{
      vers=version[1];
    }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/bugzilla"), value: tmp_version);
    set_kb_item(name:"bugzilla/installed",value:TRUE);

    ## build cpe and store it as host detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9._]+)", base:"cpe:/a:mozilla:bugzilla:");

    set_kb_item(name:string("www/", port, "/bugzilla/version"),value:vers);

    ## build cpe and store it as host detail
    cpe = build_cpe(value:vers, exp:"^([0-9._]+)", base:"cpe:/a:mozilla:bugzilla:");

    if(isnull(cpe))
      cpe = 'cpe:/a:mozilla:bugzilla';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);
    log_message(data: build_detection_report(app:"Bugzilla",
                                             version: vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded: version[0]),
                                             port: port);

  }
}
exit(0);
