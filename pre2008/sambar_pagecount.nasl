###############################################################################
# OpenVAS Vulnerability Test
# $Id: sambar_pagecount.nasl 5134 2017-01-30 08:20:15Z cfi $
#
# Sambar webserver pagecount hole
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2001 StrongHoldNet
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10711");
  script_version("$Revision: 5134 $");
  script_bugtraq_id(3091, 3092);
  script_cve_id("CVE-2001-1010");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-30 09:20:15 +0100 (Mon, 30 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Sambar webserver pagecount hole");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Vincent Renardias");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/sambar");

  tag_summary = "By default, there is a pagecount script with Sambar Web Server
  located at http://sambarserver/session/pagecount
  This counter writes its temporary files in c:\sambardirectory\tmp.
  It allows to overwrite any files on the filesystem since the 'page'
  parameter is not checked against '../../' attacks.

  Reference : http://www.securityfocus.com/archive/1/199410";

  tag_solution = "Remove this script";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/session/pagecount";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res !~ "HTTP/1\.. 404" ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, report:report );
  exit( 0 );
}

exit( 99 );