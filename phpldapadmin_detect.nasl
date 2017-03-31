###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpldapadmin_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# phpLDAPadmin Detection
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
 script_oid("1.3.6.1.4.1.25623.1.0.100395");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("phpLDAPadmin Detection");

 script_tag(name:"qod_type", value:"remote_banner");

 script_summary("Checks for the presence of phpLDAPadmin");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_xref(name : "URL" , value : "http://phpldapadmin.sourceforge.net/");

 script_tag(name : "summary" , value : "This host is running phpLDAPadmin, a web-based LDAP administration
tool for managing LDAP server.");

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

dirs = make_list_unique("/", "/phpldapadmin","/ldapadmin","/ldap","/phpldapadmin/htdocs","/ldapadmin/htdocs",cgi_dirs());

foreach dir (dirs) {

 rep_dir = dir;
 if (dir == "/") dir = "";

 url = string(dir, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;
 if( "<title>phpLDAPadmin" >< buf && "phpLDAPadmin logo" >< buf )
 {
    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "phpLDAPadmin \(([0-9.]+)\)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/phpldapadmin"), value: tmp_version);
    set_kb_item(name:"phpldapadmin/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:phpldapadmin:phpldapadmin:");
    if(isnull(cpe)) 
      cpe = 'cpe:/a:phpldapadmin:phpldapadmin';

    register_product(cpe:cpe, location:rep_dir, port:port);
    log_message(data: build_detection_report(app:"phpLDAPadmin",
                                     version:vers,
                                     install:rep_dir,
                                     cpe:cpe,
                                     concluded: version[0]),
                port: port);
 }
}
exit(0);

