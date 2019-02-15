###############################################################################
# OpenVAS Vulnerability Test
# $Id: cgi_directories.nasl 13679 2019-02-15 08:20:11Z cfischer $
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
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
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

  script_xref(name:"URL", value:"https://community.greenbone.net/c/vulnerability-tests");

  script_add_preference(name:"Maximum number of items shown for each list", type:"entry", value:"100");

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

  If you think any of this information is wrong please report it to the referenced community portal.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( http_is_cgi_scan_disabled() ) {
  log_message( port:0, data:"CGI Scanning is disabled for this host via the 'Enable CGI scanning' option within the 'Global variable settings' of the scan config in use." );
  exit( 0 );
}

function prepend_max_items_text( curReport, currentItems, maxItems ) {

  local_var curReport, currentItems, maxItems, report;

  report  = "NOTE: The 'Maximum number of items shown for each list' setting has been reached. ";
  report += "There are " + ( currentItems - maxItems ) + " additional entries available for the ";
  report += "following truncated list.";
  report += '\n\n' + curReport;
  return report;
}

maxItems = int( script_get_preference( "Maximum number of items shown for each list" ) );
if( maxItems <= 0 ) maxItems = 100;

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

cgiDirs          = cgi_dirs( port:port, host:host );
httpVersion      = get_kb_item( "http/" + port );
authRequireDirs  = http_get_kb_auth_required( port:port, host:host );
cgiList          = get_kb_list( "www/" + host + "/" + port + "/content/cgis/cgis_reporting/*" );
excludedCgiList  = get_kb_list( "www/" + host + "/" + port + "/content/excluded_cgis/*" );
dirIndexList     = get_kb_list( "www/" + host + "/" + port + "/content/dir_index" );
phpinfoList      = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/reporting" );
phpPathList      = get_kb_list( "www/" + host + "/" + port + "/content/php_physical_path" );
guardianList     = get_kb_list( "www/" + host + "/" + port + "/content/guardian" );
coffeecupList    = get_kb_list( "www/" + host + "/" + port + "/content/coffeecup" );
chOptOutList     = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_optout" );
chOptInList      = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_optin" );
chNoOptOutList   = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_nooptout" );
chObfuscatedList = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_obfuscated" );
frontpageList    = get_kb_list( "www/" + host + "/" + port + "/content/frontpage_results" );
skippedDirList   = get_kb_list( "www/" + host + "/" + port + "/content/skipped_directories" );
excludedDirList  = get_kb_list( "www/" + host + "/" + port + "/content/excluded_directories" );
srvmanualDirList = get_kb_list( "www/" + host + "/" + port + "/content/servermanual_directories" );
recursionUrlList = get_kb_list( "www/" + host + "/" + port + "/content/recursion_urls" );
maxPagesReached  = get_kb_item( "www/" + host + "/" + port + "/content/max_pages_reached" );
cgiDirExcPattern = get_kb_item( "global_settings/cgi_dirs_exclude_pattern" );
maxPagesToMirror = get_kb_item( "webmirror/max_pages_to_mirror" );
maxDirsInKb      = get_kb_item( "webmirror/max_dirs_in_kb" );
cgisExcPattern   = get_kb_item( "webmirror/cgi_scripts_exclude_pattern" );

report = 'The Hostname/IP "' + host + '" was used to access the remote host.\n\n';

if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) ) {
  report += 'Generic web application scanning is disabled for this host via the "Enable generic web application scanning" option within the "Global variable settings" of the scan config in use.\n\n';
}

if( http_get_is_marked_broken( port:port, host:host ) ) {
  report += 'This service is marked as broken and no CGI scanning is launched against it.\n\n';
}

if( no404_string = http_get_no404_string( port:port, host:host ) ) {
  if( no404_string != "HTTP" ) { #nb: Set by no404.nasl if "generally" marked broken.
    report += 'The service is responding with a 200 HTTP status code to non-existent files/urls. ';
    report += 'The following pattern is used to work around possible false detections:\n\n';
    report += no404_string + '\n\n';
  }
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

user_agent = http_get_user_agent( dont_add_oid:TRUE );
if( _http_ua_include_oid )
  user_agent = ereg_replace( string:user_agent, pattern:"(.+)$", replace:"\1 (OID:dynamic)" );

report += 'The User-Agent "' + user_agent + '" was used to access the remote host.\n\n';

if( get_kb_item( "global_settings/exclude_historic_cgi_dirs" ) ) {
  report += 'Historic /scripts and /cgi-bin are not added to the directories used for CGI scanning. ';
  report += 'You can enable this again with the "Add historic /scripts and /cgi-bin to directories for CGI scanning" ';
  report += 'option within the "Global variable settings" of the scan config in use.\n\n';
}

if( ! isnull( recursionUrlList ) ) {

  currentItems = 0;

  tmpreport  = 'A possible recursion was detected during CGI scanning:\n\n';
  tmpreport += 'The service is using a relative URL in one or more HTML references where e.g. /file1.html contains <a href="subdir/file2.html"> ';
  tmpreport += 'and a subsequent request for subdir/file2.html is linking to subdir/file2.html. This would resolves to subdir/subdir/file2.html ';
  tmpreport += 'causing a recursion. To work around this counter-measures have been enabled but the service should be fixed as well to not ';
  tmpreport += 'use such problematic links. Below an excerpt of URLs is shown to help identify those issues.\n\n';
  tmpreport += 'Syntax : URL (HTML link)\n\n';

  # Sort to not report changes on delta reports if just the order is different
  recursionUrlList = sort( recursionUrlList );

  foreach url( recursionUrlList ) {
    currentItems++;
    # Using a fixed list of five items and not the maxItems from the others is expected.
    if( currentItems >= 6 ) continue;
    tmpreport += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
  }
  report += tmpreport + '\n';
}

if( ! isnull( authRequireDirs ) ) {

  currentItems = 0;

  tmpreport  = "The following directories require authentication ";
  tmpreport += 'and are tested by the script "HTTP Brute Force Logins with default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108041)":\n\n';

  # Sort to not report changes on delta reports if just the order is different
  authRequireDirs = sort( authRequireDirs );

  foreach dir( authRequireDirs ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( cgiDirs ) ) {

  currentItems = 0;

  tmpreport = 'The following directories were used for CGI scanning:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  cgiDirs = sort( cgiDirs );

  foreach dir( cgiDirs ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
  report += 'While this is not, in and of itself, a bug, you should manually inspect ';
  report += "these directories to ensure that they are in compliance with company ";
  report += 'security standards\n\n';
}

if( ! isnull( skippedDirList ) ) {

  currentItems = 0;

  tmpreport  = "The following directories were skipped for CGI scanning because the ";
  tmpreport += "'Number of cgi directories to save into KB' setting (Current: " + maxDirsInKb;
  tmpreport += ') of the NVT Web mirroring (OID: 1.3.6.1.4.1.25623.1.0.10662) was reached:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  skippedDirList = sort( skippedDirList );

  foreach dir( skippedDirList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( excludedDirList ) ) {

  currentItems = 0;

  tmpreport  = "The following directories were excluded from CGI scanning because";
  tmpreport += ' the "Regex pattern to exclude directories from CGI scanning" setting of the NVT';
  tmpreport += ' "Global variable settings" (OID: 1.3.6.1.4.1.25623.1.0.12288) for this scan was: ';
  tmpreport += '"' + cgiDirExcPattern + '"\n\n';

  # Sort to not report changes on delta reports if just the order is different
  excludedDirList = sort( excludedDirList );

  foreach dir( excludedDirList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += report_vuln_url( port:port, url:dir, url_only:TRUE ) + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( srvmanualDirList ) ) {

  currentItems = 0;

  tmpreport  = "The following directories were excluded from CGI scanning because";
  tmpreport += ' of the "Exclude directories containing detected known server manuals from CGI scanning"';
  tmpreport += ' setting of the NVT "Global variable settings" (OID: 1.3.6.1.4.1.25623.1.0.12288):\n\n';

  # Sort to not report changes on delta reports if just the order is different
  srvmanualDirList = sort( srvmanualDirList );

  foreach dir( srvmanualDirList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += dir + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( dirIndexList ) ) {

  currentItems = 0;

  tmpreport = 'Directory index found at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  dirIndexList = sort( dirIndexList );

  foreach dirIndex( dirIndexList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += dirIndex + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( phpinfoList ) ) {

  currentItems = 0;

  tmpreport = 'Extraneous phpinfo() script found at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  phpinfoList = sort( phpinfoList );

  foreach phpinfo( phpinfoList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += phpinfo + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( phpPathList ) ) {

  currentItems = 0;

  tmpreport = 'PHP script discloses physical path at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  phpPathList = sort( phpPathList );

  foreach phpPath( phpPathList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += phpPath + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}


if( ! isnull( guardianList ) ) {

  currentItems = 0;

  tmpreport = 'The following files seems to have been "encrypted" with HTML Guardian:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  guardianList = sort( guardianList );

  foreach guardian( guardianList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += guardian + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n\n';
  report += 'HTML Guardian is a tool which claims to encrypt web pages, whereas it simply
  does a transposition of the content of the page. It is is no way a safe way to make sure your
  HTML pages are protected.

  See also : http://www.securityfocus.com/archive/1/315950
  BID : 7169\n\n';
}

if( ! isnull( coffeecupList ) ) {

  currentItems = 0;

  tmpreport = 'The following files seems to contain links "protected" by CoffeCup:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  coffeecupList = sort( coffeecupList );

  foreach coffeecup( coffeecupList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += coffeecup + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n\n';
  report += 'CoffeeCup Wizard is a tool which claims to encrypt links to web pages,
  to force users to authenticate before they access the links. However, the "encryption"
  used is a simple transposition method which can be decoded without the need of knowing
  a real username and password.

  BID : 6995 7023\n\n';
}

if( ! isnull( frontpageList ) ) {

  currentItems = 0;

  tmpreport = 'FrontPage form stores results in web root at:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  frontpageList = sort( frontpageList );

  foreach frontpage( frontpageList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += frontpage + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( chOptOutList ) || ! isnull( chOptInList ) ||
    ! isnull( chNoOptOutList ) || ! isnull( chObfuscatedList ) ) {

  currentItems = 0;

  tmpreport = 'The Coinhive JavaScript Miner was found embedded into the following pages:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  if( chOptOutList )     chOptOutList     = sort( chOptOutList );
  if( chOptInList )      chOptInList      = sort( chOptInList );
  if( chNoOptOutList )   chNoOptOutList   = sort( chNoOptOutList );
  if( chObfuscatedList ) chObfuscatedList = sort( chObfuscatedList );

  foreach chOptOut( chOptOutList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += chOptOut + ' (OptOut configured for the user)\n';
  }

  foreach chOptIn( chOptInList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += chOptIn + ' (Opt-In by the user explicitly required)\n';
  }

  foreach chNoOptOut( chNoOptOutList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += chNoOptOut + ' (No OptOut configured for the user, might be malicious)\n';
  }

  foreach chObfuscated( chObfuscatedList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += chObfuscated + ' (Obfuscated, look out for code containing \\x73\\x70\\x6C\\x69\\x74. Very likely malicious)\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( maxPagesReached ) {
  report += 'The "Number of pages to mirror" setting (Current: ' + maxPagesToMirror;
  report += ') of the NVT "Web mirroring" (OID: 1.3.6.1.4.1.25623.1.0.10662) was reached.';
  report += ' Raising this limit allows to mirror this host more thoroughly';
  report += ' but might increase the scanning time.\n\n';
}

if( ! isnull( cgiList ) ) {

  currentItems = 0;

  tmpreport = 'The following CGIs were discovered:\n\nSyntax : cginame (arguments [default value])\n\n';

  # Sort to not report changes on delta reports if just the order is different
  cgiList = sort( cgiList );

  foreach cgi( cgiList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += cgi + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport + '\n';
}

if( ! isnull( excludedCgiList ) ) {

  currentItems = 0;

  tmpreport  = "The following cgi scripts were excluded from CGI scanning because";
  tmpreport += ' of the "Regex pattern to exclude cgi scripts" setting of the NVT';
  tmpreport += ' "Web mirroring" (OID: 1.3.6.1.4.1.25623.1.0.10662) for this scan was: ';
  tmpreport += '"' + cgisExcPattern + '"\n\n';
  tmpreport += 'Syntax : cginame (arguments [default value])\n\n';

  # Sort to not report changes on delta reports if just the order is different
  excludedCgiList = sort( excludedCgiList );

  foreach cgi( excludedCgiList ) {
    currentItems++;
    if( currentItems >= maxItems ) continue;
    tmpreport += cgi + '\n';
  }
  if( currentItems >= maxItems )
    tmpreport = prepend_max_items_text( curReport:tmpreport, currentItems:currentItems, maxItems:maxItems );
  report += tmpreport;
}

log_message( data:report, port:port );
exit( 0 );