# OpenVAS Vulnerability Test
# $Id: xoops_viewtopic_xss.nasl 3502 2016-06-13 16:52:56Z mime $
# Description: Xoops viewtopic.php Cross Site Scripting Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on Noam Rathaus script
# Updated: 05/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server contains a PHP script that is prone to cross-
  site scripting attacks.

  Description :

  The weblinks module of XOOPS contains a file named 'viewtopic.php' in
  the '/modules/newbb' directory.  The code of the module insufficently
  filters out user provided data.  The URL parameter used by
  'viewtopic.php' can be used to insert malicious HTML and/or JavaScript
  in to the web page.";

tag_solution = "Unknown at this time.";

#  Ref: Ben Drysdale <ben@150bpm.co.uk>

if(description)
{
  script_id(15480);
  script_version("$Revision: 3502 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 18:52:56 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2756");
 script_bugtraq_id(9497);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  name = "Xoops viewtopic.php Cross Site Scripting Vulnerability";
  script_name(name);

  summary = "Detect Xoops viewtopic.php XSS";
  script_summary(summary);
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  family = "Web application abuses";
  script_family(family);
  script_dependencies("cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securitytracker.com/alerts/2004/Jan/1008849.html");
  exit(0);
}

include("http_func.inc");

xoopsPort = get_http_port(default:80);

if(!get_port_state(xoopsport)){
  exit(0);
}

foreach path (make_list("/", "/xoops/htdocs", "/xoops/htdocs/install", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);
  if("XOOPS" >< rcvRes)
  {
    sndReq = http_get(item:string(path, '/modules/newbb/viewtopic.php?topic_id' +
            '=14577&forum=2\"><script>foo</script>'), port:xoopsPort);
    rcvRes = http_send_recv(port:xoopsPort, data:sndReq);
    if(rcvRes =~ "HTTP/1\.. 200" && "<script>foo</script>" >< rcvRes )
    {
      security_message(xoopsport);
      exit(0);
    }
  }
}
