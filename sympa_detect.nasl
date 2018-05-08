###################################################################
# OpenVAS Vulnerability Test
# $Id: sympa_detect.nasl 9745 2018-05-07 11:45:41Z cfischer $
#
# Sympa Detection
#
# LSS-NVT-2009-013
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.102013");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9745 $");
 script_tag(name:"last_modification", value:"$Date: 2018-05-07 13:45:41 +0200 (Mon, 07 May 2018) $");
 script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Sympa Detection");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2009 LSS");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_family("Product detection");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 
 script_xref(name : "URL" , value : "http://www.sympa.org/");

 script_tag(name : "summary" , value : "The remote host is running Sympa, an open source (GNU GPL) mailing list management (MLM) software
 suite written in Perl.");
 script_tag(name:"qod_type", value:"remote_banner");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

dirs = make_list_unique( "/sympa", cgi_dirs( port:port ) );

foreach dir( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/", port:port );

  # Check if it is Sympa
  pat = 'Powered by ([^>]*>)?Sympa ?v?([0-9.]+)';
  match = egrep( pattern:pat,string:buf, icase:1 );
    
  if( match || egrep( pattern:"<meta name=.generator. content=.Sympa", string:buf, icase:1 ) ) {
      
    # Installation found, extract version
    item = eregmatch( pattern:pat, string:match, icase:1 );
    ver = item[2];

    # If version couldn't be extracted, mark as unknown
    if( ! ver ) ver="unknown";

    tmp_version = ver + " under " + install;
    set_kb_item( name:"www/" + port + "/sympa", value:tmp_version );
   
    ## build cpe and store it as host_detail
    cpe = build_cpe( value:ver, exp:"^([0-9.]+)", base:"cpe:/a:sympa:sympa:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:sympa:sympa';

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Sympa",
                                                   version:ver,
                                                   install:install,
                                                   cpe:cpe,
                                                   concluded:item[0]),
                                                   port:port);
  }
}

exit( 0 );