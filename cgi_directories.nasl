###############################################################################
# OpenVAS Vulnerability Test
# $Id: cgi_directories.nasl 8106 2017-12-13 14:42:54Z cfischer $
#
# CGI Scanning Consolidation
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111038");
  script_version("$Revision: 8106 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-13 15:42:54 +0100 (Wed, 13 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-09-14 07:00:00 +0200 (Mon, 14 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CGI Scanning Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_twonky_server_detect.nasl",
  "gb_owncloud_detect.nasl", "gb_adobe_aem_remote_detect.nasl", "gb_libreoffice_online_detect.nasl",
  "gb_apache_activemq_detect.nasl", "gb_orientdb_server_detect.nasl"); # gb_* are additional dependencies setting auth_required
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The script consolidates various information for CGI scanning.

  This information is based on the following scripts / settings:

  - HTTP-Version Detection (OID: 1.3.6.1.4.1.25623.1.0.100034)

  - No 404 check (OID: 1.3.6.1.4.1.25623.1.0.10386)

  - Web mirroring / webmirror.nasl (OID: 1.3.6.1.4.1.25623.1.0.10662)

  - Directory Scanner / DDI_Directory_Scanner.nasl (OID: 1.3.6.1.4.1.25623.1.0.11032)

  - The configured 'cgi_path' within the 'Scanner Preferences' of the scan config in use

  - The configured 'Enable CGI scanning', 'Enable generic web application scanning' and 
    'Add historic /scripts and /cgi-bin to directories for CGI scanning' within the
    'Global variable settings' of the scan config in use

  If you think any of these are wrong please report to openvas-plugins@wald.intevation.org");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( get_kb_item( "Settings/disable_cgi_scanning" ) ) {
  log_message( port:0, data:"CGI Scanning is disabled for this host via the 'Enable CGI scanning' option within the 'Global variable settings' of the scan config in use." );
  exit( 0 );
}

port = get_http_port( default:80 );

cgiDirs = cgi_dirs( port:port );
authRequireDirs = get_kb_list( "www/" + port + "/content/auth_required" );
cgiList = get_kb_list( "www/" + port + "/content/cgis/*" );
excludedCgiList = get_kb_list( "www/" + port + "/content/excluded_cgis/*" );
dirIndexList = get_kb_list( "www/" + port + "/content/dir_index" );
phpinfoList = get_kb_list( "www/" + port + "/content/phpinfo_script" );
phpPathList = get_kb_list( "www/" + port + "/content/php_pysical_path" );
guardianList = get_kb_list( "www/" + port + "/content/guardian" );
coffeecupList = get_kb_list( "www/" + port + "/content/coffeecup" );
frontpageList = get_kb_list( "www/" + port + "/content/frontpage_results" );
skippedDirList = get_kb_list( "www/" + port + "/content/skipped_directories" );
excludedDirList = get_kb_list( "www/" + port + "/content/excluded_directories" );
httpVersion = get_kb_item( "http/" + port );
maxPagesReached = get_kb_item( "www/" + port + "/content/max_pages_reached" );

#report = 'The hostname "' + http_host_name( port:port ) + '" is used.\n\n'; #TODO is this forking?

#TODO: Add no404.nasl

if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) ) {
  report += 'Generic web application scanning is disabled for this host via the "Enable generic web application scanning" option within the "Global variable settings" of the scan config in use.\n\n';
}

if( get_kb_item( "Services/www/" + port + "/broken" ) ) {
  report += 'This service is marked as broken and no CGI scanning is launched against it.\n\n';
}

if( httpVersion == "10" ) {
  report += 'Requests to this service are done via HTTP/1.0.\n\n';
} else if( httpVersion == "11" ) {
  report += 'Requests to this service are done via HTTP/1.1.\n\n';
}

if( can_host_php( port:port ) ) {
  report += 'This service seems to be able to host PHP scripts.\n\n';
} else {
  report += 'This service seems to be NOT able to host PHP scripts.\n\n';
}

if( can_host_asp( port:port ) ) {
  report += 'This service seems to be able to host ASP scripts.\n\n';
} else {
  report += 'This service seems to be NOT able to host ASP scripts.\n\n';
}

if( get_kb_item( "global_settings/exclude_historic_cgi_dirs" ) ) {
  report += 'Historic /scripts and /cgi-bin are not added to the directories used for CGI scanning. ';
  report += 'You can enable this again with the "Add historic /scripts and /cgi-bin to directories for CGI scanning" ';
  report += 'option within the "Global variable settings" of the scan config in use.\n\n';
}

if( ! isnull( authRequireDirs ) ) {

  report += "The following directories require authentication ";
  report += 'and are tested by the script "HTTP Brute Force Logins with default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108041)":\n\n';

  # Sort to not report changes on delta reports if just the order is different
  authRequireDirs = sort( authRequireDirs );

  foreach dir( authRequireDirs ) {
    report += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  report += '\n';
}

if( ! isnull( cgiDirs ) ) {

  report += 'The following directories were used for CGI scanning:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  cgiDirs = sort( cgiDirs );

  foreach dir( cgiDirs ) {
    report += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  report += '\nWhile this is not, in and of itself, a bug, you should manually inspect ';
  report += "these directories to ensure that they are in compliance with company ";
  report += 'security standards\n\n';
}

if( ! isnull( skippedDirList ) ) {

  report += "The following directories were skipped for CGI scanning because";
  report += " the 'Number of cgi directories to save into KB' setting of the NVT";
  report += ' Web mirroring (OID: 1.3.6.1.4.1.25623.1.0.10662) was reached:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  skippedDirList = sort( skippedDirList );

  foreach dir( skippedDirList ) {
    report += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  report += '\n';
}

if( ! isnull( excludedDirList ) ) {

  report += "The following directories were excluded from CGI scanning because";
  report += ' of the "Regex pattern to exclude directories from CGI scanning" setting of the NVT';
  report += ' "Global variable settings" (OID: 1.3.6.1.4.1.25623.1.0.12288):\n\n';

  # Sort to not report changes on delta reports if just the order is different
  excludedDirList = sort( excludedDirList );

  foreach dir( excludedDirList ) {
    report += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  report += '\n';
}

if( ! isnull( dirIndexList ) ) {

  report += 'Directory index found at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  dirIndexList = sort( dirIndexList );

  foreach dirIndex( dirIndexList ) {
    report += dirIndex + '\n';
  }
  report += '\n';
}

if( ! isnull( phpinfoList ) ) {

  report += 'Extraneous phpinfo() script found at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  phpinfoList = sort( phpinfoList );

  foreach phpinfo( phpinfoList ) {
    report += phpinfo + '\n';
  }
  report += '\n';
}

if( ! isnull( phpPathList ) ) {

  report += 'PHP script discloses physical path at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  phpPathList = sort( phpPathList );

  foreach phpPath( phpPathList ) {
    report += phpPath + '\n';
  }
  report += '\n';
}


if( ! isnull( guardianList ) ) {

  report += 'The following files seems to have been "encrypted" with HTML Guardian:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  guardianList = sort( guardianList );

  foreach guardian( guardianList ) {
    report += guardian + '\n';
  }

  report += '\n\nHTML Guardian is a tool which claims to encrypt web pages, whereas it simply
  does a transposition of the content of the page. It is is no way a safe way to make sure your
  HTML pages are protected.

  See also : http://www.securityfocus.com/archive/1/315950
  BID : 7169\n\n';
}

if( ! isnull( coffeecupList ) ) {

  report += 'The following files seems to contain links "protected" by CoffeCup:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  coffeecupList = sort( coffeecupList );

  foreach coffeecup( coffeecupList ) {
    report += coffeecup + '\n';
  }

  report += '\n\nCoffeeCup Wizard is a tool which claims to encrypt links to web pages,
  to force users to authenticate before they access the links. However, the "encryption"
  used is a simple transposition method which can be decoded without the need of knowing
  a real username and password.

  BID : 6995 7023\n\n';
}

if( ! isnull( frontpageList ) ) {

  report += 'FrontPage form stores results in web root at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  frontpageList = sort( frontpageList );

  foreach frontpage( frontpageList ) {
    report += frontpage + '\n';
  }
  report += '\n';
}

if( maxPagesReached ) {

  report += 'The "Number of pages to mirror" setting of the NVT';
  report += ' "Web mirroring" (OID: 1.3.6.1.4.1.25623.1.0.10662) was reached.';
  report += ' Raising this limit allows to mirror this host more thoroughly';
  report += ' but might increase the scanning time.\n\n';
}

if( ! isnull( cgiList ) ) {

  report += 'The following CGIs were discovered:\n\nSyntax : cginame (arguments [default value])\n\n';

  # Sort to not report changes on delta reports if just the order is different
  cgiList = sort( cgiList );

  foreach cgi( cgiList ) {
    report += cgi + '\n';
  }
  report += '\n';
}

if( ! isnull( excludedCgiList ) ) {

  report += "The following cgi scripts were excluded from CGI scanning because";
  report += ' of the "Regex pattern to exclude cgi scripts" setting of the NVT';
  report += ' "Web mirroring" (OID: 1.3.6.1.4.1.25623.1.0.10662):\n\n';
  report += 'Syntax : cginame (arguments [default value])\n\n';

  # Sort to not report changes on delta reports if just the order is different
  excludedCgiList = sort( excludedCgiList );

  foreach cgi( excludedCgiList ) {
    report += cgi + '\n';
  }
}

log_message( data:report, port:port );

exit( 0 );
