###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_Directory_Scanner.nasl 5273 2017-02-12 13:11:18Z cfi $
#
# Directory Scanner
#
# Authors:
# H D Moore <hdm@digitaloffense.net>
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11032");
  script_version("$Revision: 5273 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-12 14:11:18 +0100 (Sun, 12 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_xref(name:"OWASP", value:"OWASP-CM-006");
  script_name("Directory Scanner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "embedded_web_server_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_timeout(900);

  script_tag(name:"summary", value:"This plugin attempts to determine the presence of various
  common dirs on the remote web server");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("404.inc"); # For errmessages_404 list

function check_cgi_dir( dir ) {

  local_var req, res;

  req = http_get( item:dir + "/non-existent"  + rand(), port:port );
  res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );
  if( res == NULL ) failedReqs++;

  if( egrep( pattern:"^HTTP.* 404 .*", string:res ) ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

function check_req_send( port, url ) {

  soc = http_open_socket( port );
  if( ! soc ) return( 0 );
  req = http_get( item:url, port:port );
  send( socket:soc, data:req );
  return( soc );
}

function check_req_recv( soc ) {

  if( soc == 0 ) return( 0 );

  if( fake404 == "BadString0987654321*DDI*" ) {
    http_resp = recv_line( socket:soc, length:255 );
  } else {
    http_resp = http_recv( socket:soc );
  }

  http_close_socket( soc );
  return( http_resp );
}

function check_dir_list (dir) {

  for( CDC = 0; dirs[CDC]; CDC++ ) {
    if( dirs[CDC] == dir ) {
      return( 1 );
    }
  }
  return( 0 );
}

function check_discovered_list( dir ) {
  for( CDL = 0; discovered[CDL]; CDL++ ) {
    if( discovered[CDL] == dir) {
      return( 1 );
    }
  }
  return( 0 );
}

function add_discovered_list( dir ) {
  if( check_discovered_list( dir:dir ) == 0) {
    discovered[discovered_last] = dir;
    discovered_last++;

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    dir_key = "www/" + port + "/content/directories";
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir, "'\n" );
    set_kb_item( name:dir_key, value:dir );
  }
}

function check_auth_dir_list( dir ) {
  for( ADL = 0; authDir[ADL]; ADL++ ) {
    if( authDir[ADL] == dir) {
      return( 1 );
    }
  }
  return( 0 );
}

function add_auth_dir_list( dir ) {
  if( check_auth_dir_list( dir:dir ) == 0) {
    authDir[authDir_last] = dir;
    authDir_last++;

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    dir_key = "www/" + port + "/content/auth_required";
    replace_kb_item( name:"www/content/auth_required", value:TRUE );
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir, "'\n" );
    set_kb_item( name:dir_key, value:dir );
  }
}

CGI_Dirs = make_list();

i = 0;

dirs[i] = ".cobalt";		score[i++] = 1;
dirs[i++] = "1";
dirs[i++] = "10";
dirs[i++] = "2";
dirs[i++] = "3";
dirs[i++] = "4";
dirs[i++] = "5";
dirs[i++] = "6";
dirs[i++] = "7";
dirs[i++] = "8";
dirs[i++] = "9";
dirs[i] = "AdminWeb"; 		score[i++] = 1;
dirs[i] = "Admin_files"; 	score[i++] = 1;
dirs[i] = "Administration"; 	score[i++] = 1;
dirs[i] = "AdvWebAdmin"; 	score[i++] = 1;
dirs[i++] = "Agent";
dirs[i++] = "Agents";
dirs[i++] = "Album";
dirs[i++] = "CS";
dirs[i++] = "CVS";
dirs[i++] = "DMR";
dirs[i++] = "DocuColor";
dirs[i++] = "GXApp";
dirs[i++] = "HB";
dirs[i++] = "HBTemplates";
dirs[i++] = "IBMWebAS";
dirs[i] = "Install";		score[i++] = 1;
dirs[i++] = "JBookIt";
dirs[i++] = "Log";
dirs[i] = "Mail";		score[i++] = 1;
dirs[i++] = "Msword";
dirs[i++] = "NSearch";
dirs[i++] = "NetDynamic";
dirs[i++] = "NetDynamics";
dirs[i] = "News";		score[i++] = 1;
dirs[i] = "PDG_Cart";		score[i++] = 1;
dirs[i] = "README";		score[i++] = 1;
dirs[i++] = "ROADS";
dirs[i] = "Readme";		score[i++] = 1;
dirs[i++] = "SilverStream";
dirs[i] = "Stats";		score[i++] = 1;
dirs[i] = "StoreDB";		score[i++] = 1;
dirs[i++] = "Templates";
dirs[i] = "ToDo";		score[i++] = 1;
dirs[i++] = "WebBank";
dirs[i] = "WebCalendar";	score[i++] = 1;
dirs[i++] = "WebDB";
dirs[i++] = "WebShop";
dirs[i] = "WebTrend";		score[i++] = 1;
dirs[i++] = "Web_store";
dirs[i++] = "XSL";
dirs[i++] = "_ScriptLibrary";
dirs[i] = "_backup";		score[i++] = 1;
dirs[i++] = "_derived";
dirs[i] = "_errors";		score[i++] = 1;
dirs[i++] = "_fpclass";
dirs[i++] = "_mem_bin";
dirs[i++] = "_notes";
dirs[i++] = "_objects";
dirs[i++] = "_old";
dirs[i++] = "_pages";
dirs[i] = "_passwords";		score[i++] = 1;
dirs[i] = "_private";		score[i++] = 1;
dirs[i] = "_scripts";		score[i] = 1;		exec[i++] = 1;
dirs[i++] = "_sharedtemplates";
dirs[i] = "_tests";		score[i++] = 1;
dirs[i++] = "_themes";
dirs[i] = "_vti_bin";		score[i++] = 1;
dirs[i] = "_vti_bot";		score[i++] = 1;
dirs[i] = "_vti_log";		score[i++] = 1;
dirs[i] = "_vti_pvt";		score[i++] = 1;
dirs[i] = "_vti_shm";		score[i++] = 1;
dirs[i] = "_vti_txt";		score[i++] = 1;
dirs[i++] = "a";
dirs[i++] = "acceso";
dirs[i] = "access";		score[i++] = 1;
dirs[i++] = "accesswatch";
dirs[i++] = "acciones";
dirs[i] = "account";		score[i++] = 1;
dirs[i] = "accounting";		score[i++] = 1;
dirs[i++] = "activex";
dirs[i] = "adm";		score[i++] = 1;
dirs[i++] = "admcgi";
dirs[i++] = "admentor";
dirs[i] = "admin";		score[i++] = 1;
dirs[i] = "admin-bak";		score[i++] = 1;
dirs[i] = "admin-old";		score[i++] = 1;
dirs[i] = "admin.back";		score[i++] = 1;
dirs[i] = "admin_";		score[i++] = 1;
dirs[i] = "administration";	score[i++] = 1;
dirs[i] = "administrator";	score[i++] = 1;
dirs[i] = "adminuser";		score[i++] = 1;
dirs[i] = "adminweb";		score[i++] = 1;
dirs[i++] = "admisapi";
dirs[i++] = "agentes";
dirs[i] = "analog";		score[i++] = 1;
dirs[i++] = "anthill";
dirs[i++] = "apache";
dirs[i++] = "app";
dirs[i++] = "applets";
dirs[i++] = "application";
dirs[i++] = "applications";
dirs[i++] = "apps";
dirs[i++] = "ar";
dirs[i] = "archive";		score[i++] = 1;
dirs[i] = "archives";		score[i++] = 1;
dirs[i] = "asp";		score[i] = 1;		exec[i++] = 1;
dirs[i++] = "atc";
dirs[i] = "auth";		score[i++] = 1;
dirs[i] = "authadmin";		score[i++] = 1;
dirs[i++] = "aw";
dirs[i++] = "ayuda";
dirs[i++] = "b";
dirs[i++] = "b2-include";
dirs[i++] = "back";
dirs[i++] = "backend";
dirs[i] = "backup";		score[i++] = 1;
dirs[i] = "backups";		score[i++] = 1;
dirs[i] = "bak";		score[i++] = 1;
dirs[i++] = "banca";
dirs[i++] = "banco";
dirs[i++] = "bank";
dirs[i++] = "banner";
dirs[i++] = "banner01";
dirs[i++] = "banners";
dirs[i++] = "batch";
dirs[i++] = "bb-dnbd";
dirs[i++] = "bbv";
dirs[i++] = "bdata";
dirs[i++] = "bdatos";
dirs[i++] = "beta";
dirs[i++] = "billpay";
dirs[i++] = "bin";
dirs[i++] = "boadmin";
dirs[i++] = "boot";
dirs[i++] = "btauxdir";
dirs[i++] = "bug";
dirs[i++] = "bugs";
dirs[i++] = "bugzilla";
dirs[i++] = "buy";
dirs[i++] = "buynow";
dirs[i++] = "c";
dirs[i++] = "cache-stats";
dirs[i++] = "caja";
dirs[i++] = "card";
dirs[i++] = "cards";
dirs[i++] = "cart";
dirs[i++] = "cash";
dirs[i++] = "caspsamp";
dirs[i++] = "catalog";
dirs[i] = "cbi-bin";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "ccard";		score[i++] = 1;
dirs[i] = "ccards";		score[i++] = 1;
dirs[i++] = "cd";
dirs[i] = "cd-cgi";		score[i] = 1;		exec[i++] = 1;
dirs[i++] = "cdrom";
dirs[i++] = "ce_html";
dirs[i++] = "cert";
dirs[i++] = "certificado";
dirs[i++] = "certificate";
dirs[i++] = "cfappman";
dirs[i++] = "cfdocs";
dirs[i] = "cfide";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-auth";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-bin";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-bin2";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-csc";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-lib";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-local";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-scripts";	score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-shl";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-shop";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-sys";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-weddico"; 	score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgi-win";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgibin";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgilib";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgis";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgiscripts";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "cgiwin";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "class";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "classes";		score[i] = 1;		exec[i++] = 1;
dirs[i++] = "cliente";
dirs[i++] = "clientes";
dirs[i++] = "cm";
dirs[i++] = "cmsample";
dirs[i++] = "cobalt-images";
dirs[i++] = "code";
dirs[i++] = "comments";
dirs[i++] = "common";
dirs[i++] = "communicator";
dirs[i++] = "compra";
dirs[i++] = "compras";
dirs[i++] = "compressed";
dirs[i++] = "conecta";
dirs[i++] = "conf";
dirs[i] = "config";		score[i++] = 1;
dirs[i++] = "connect";
dirs[i++] = "console";
dirs[i++] = "controlpanel";
dirs[i++] = "core";
dirs[i++] = "corp";
dirs[i++] = "correo";
dirs[i++] = "counter";
dirs[i] = "credit";		score[i++] = 1;
dirs[i++] = "cron";
dirs[i++] = "crons";
dirs[i++] = "crypto";
dirs[i++] = "csr";
dirs[i++] = "css";
dirs[i++] = "cuenta";
dirs[i++] = "cuentas";
dirs[i++] = "currency";
dirs[i] = "customers";		score[i++] = 1;
dirs[i++] = "cvsweb";
dirs[i++] = "cybercash";
dirs[i++] = "d";
dirs[i++] = "darkportal";
dirs[i++] = "dat";
dirs[i++] = "dav";
dirs[i++] = "data";
dirs[i] = "database";		score[i++] = 1;
dirs[i] = "databases";		score[i++] = 1;
dirs[i] = "datafiles";		score[i++] = 1;
dirs[i++] = "dato";
dirs[i++] = "datos";
dirs[i] = "db";			score[i++] = 1;
dirs[i] = "dbase";		score[i++] = 1;
dirs[i++] = "dcforum";
dirs[i++] = "ddreport";
dirs[i++] = "ddrint";
dirs[i] = "demo";		score[i++] = 1;
dirs[i++] = "demoauct";
dirs[i++] = "demomall";
dirs[i] = "demos";		score[i++] = 1;
dirs[i++] = "design";
dirs[i] = "dev";		score[i++] = 1;
dirs[i] = "devel";		score[i++] = 1;
dirs[i++] = "development";
dirs[i++] = "dir";
dirs[i] = "directory";		score[i++] = 1;
dirs[i++] = "directorymanager";
dirs[i++] = "dl";
dirs[i++] = "dm";
dirs[i++] = "dms";
dirs[i++] = "dms0";
dirs[i++] = "dmsdump";
dirs[i] = "doc";		score[i++] = 1;
dirs[i++] = "doc-html";
dirs[i++] = "doc1";
dirs[i++] = "docs";
dirs[i++] = "docs1";
dirs[i] = "document";		score[i++] = 1;
dirs[i] = "documents";		score[i++] = 1;
dirs[i++] = "down";
dirs[i] = "download";		score[i++] = 1;
dirs[i] = "downloads";		score[i++] = 1;
dirs[i++] = "dump";
dirs[i++] = "durep";
dirs[i++] = "e";
dirs[i++] = "easylog";
dirs[i++] = "eforum";
dirs[i++] = "ejemplo";
dirs[i++] = "ejemplos";
dirs[i] = "email";		score[i++] = 1;
dirs[i++] = "emailclass";
dirs[i++] = "employees";
dirs[i++] = "empoyees";
dirs[i++] = "empris";
dirs[i++] = "envia";
dirs[i++] = "enviamail";
dirs[i++] = "error";
dirs[i++] = "errors";
dirs[i++] = "es";
dirs[i++] = "estmt";
dirs[i++] = "etc";
dirs[i++] = "example";
dirs[i++] = "examples";
dirs[i++] = "exc";
dirs[i++] = "excel";
dirs[i++] = "exchange";
dirs[i++] = "exe";
dirs[i++] = "exec";
dirs[i++] = "export";
dirs[i++] = "external";
dirs[i++] = "f";
dirs[i++] = "fbsd";
dirs[i++] = "fcgi-bin";
dirs[i++] = "file";
dirs[i++] = "filemanager";
dirs[i++] = "files";
dirs[i++] = "foldoc";
dirs[i++] = "form";
dirs[i++] = "form-totaller";
dirs[i++] = "forms";
dirs[i++] = "formsmgr";
dirs[i++] = "forum";
dirs[i++] = "forums";
dirs[i++] = "foto";
dirs[i++] = "fotos";
dirs[i++] = "fpadmin";
dirs[i++] = "fpdb";
dirs[i++] = "fpsample";
dirs[i++] = "framesets";
dirs[i++] = "ftp";
dirs[i++] = "ftproot";
dirs[i++] = "g";
dirs[i++] = "gfx";
dirs[i++] = "global";
dirs[i++] = "grocery";
dirs[i++] = "guest";
dirs[i++] = "guestbook";
dirs[i++] = "guests";
dirs[i++] = "help";
dirs[i++] = "helpdesk";
dirs[i] = "hidden";		score[i++] = 1;
dirs[i++] = "hide";
dirs[i++] = "hit_tracker";
dirs[i++] = "hitmatic";
dirs[i] = "hlstats";		score[i++] = 1;
dirs[i++] = "home";
dirs[i++] = "hostingcontroller";
dirs[i++] = "ht";
dirs[i] = "htbin";		score[i] = 1;		exec[i++] = 1;
dirs[i] = "htdocs";		score[i++] = 1;
dirs[i++] = "html";
dirs[i++] = "hyperstat";
dirs[i++] = "ibank";
dirs[i++] = "ibill";
dirs[i++] = "icons";
dirs[i++] = "idea";
dirs[i++] = "ideas";
dirs[i] = "iisadmin"; 		score[i++] = 1;
dirs[i] = "iissamples";		score[i++] = 1;
dirs[i++] = "image";
dirs[i++] = "imagenes";
dirs[i++] = "imagery";
dirs[i++] = "images";
dirs[i++] = "img";
dirs[i++] = "imp";
dirs[i++] = "import";
dirs[i++] = "impreso";
dirs[i++] = "inc";
dirs[i] = "include";		score[i++] = 1;
dirs[i] = "includes";		score[i++] = 1;
dirs[i] = "incoming";		score[i++] = 1;
dirs[i++] = "info";
dirs[i++] = "information";
dirs[i++] = "ingresa";
dirs[i++] = "ingreso";
dirs[i++] = "install";
dirs[i++] = "internal";
dirs[i] = "intranet";		score[i++] = 1;
dirs[i++] = "inventory";
dirs[i++] = "invitado";
dirs[i++] = "isapi";
dirs[i++] = "japidoc";
dirs[i++] = "java";
dirs[i++] = "javascript";
dirs[i++] = "javasdk";
dirs[i++] = "javatest";
dirs[i++] = "jave";
dirs[i++] = "jdbc";
dirs[i++] = "job";
dirs[i++] = "jrun";
dirs[i++] = "js";
dirs[i++] = "jserv";
dirs[i++] = "jslib";
dirs[i++] = "jsp";
dirs[i++] = "junk";
dirs[i++] = "kiva";
dirs[i++] = "labs";
dirs[i++] = "lcgi";
dirs[i++] = "lib";
dirs[i++] = "libraries";
dirs[i++] = "library";
dirs[i++] = "libro";
dirs[i++] = "links";
dirs[i++] = "linux";
dirs[i++] = "loader";
dirs[i] = "log";		score[i++] = 1;
dirs[i++] = "logfile";
dirs[i++] = "logfiles";
dirs[i++] = "logg";
dirs[i++] = "logger";
dirs[i++] = "logging";
dirs[i] = "login";		score[i++] = 1;
dirs[i] = "logon";		score[i++] = 1;
dirs[i] = "logs";		score[i++] = 1;
dirs[i] = "lost+found";		score[i++] = 1;
dirs[i++] = "mail";
dirs[i++] = "mail_log_files";
dirs[i++] = "mailman";
dirs[i++] = "mailroot";
dirs[i++] = "makefile";
dirs[i++] = "mall_log_files";
dirs[i++] = "manage";
dirs[i++] = "manual";
dirs[i++] = "marketing";
dirs[i++] = "members";
dirs[i++] = "message";
dirs[i++] = "messaging";
dirs[i++] = "metacart";
dirs[i++] = "misc";
dirs[i++] = "mkstats";
dirs[i++] = "movimientos";
dirs[i++] = "mqseries";
dirs[i++] = "msql";
dirs[i++] = "mysql";
dirs[i] = "mysql_admin";	score[i++] = 1;
dirs[i++] = "ncadmin";
dirs[i++] = "nchelp";
dirs[i++] = "ncsample";
dirs[i++] = "netbasic";
dirs[i++] = "netcat";
dirs[i++] = "netmagstats";
dirs[i++] = "netscape";
dirs[i++] = "netshare";
dirs[i++] = "nettracker";
dirs[i++] = "new";
dirs[i++] = "nextgeneration";
dirs[i++] = "nl";
dirs[i++] = "noticias";
dirs[i++] = "objects";
dirs[i++] = "odbc";
dirs[i] = "old";		score[i++] = 1;
dirs[i] = "old_files";		score[i++] = 1;
dirs[i] = "oldfiles";		score[i++] = 1;
dirs[i++] = "oprocmgr-service";
dirs[i++] = "oprocmgr-status";
dirs[i] = "oracle";		score[i++] = 1;
dirs[i++] = "oradata";
dirs[i++] = "order";
dirs[i++] = "orders";
dirs[i++] = "outgoing";
dirs[i++] = "owners";
dirs[i++] = "pages";
dirs[i++] = "passport";
dirs[i] = "password";		score[i++] = 1;
dirs[i] = "passwords";		score[i++] = 1;
dirs[i] = "payment";		score[i++] = 1;
dirs[i] = "payments";		score[i++] = 1;
dirs[i++] = "pccsmysqladm";
dirs[i++] = "perl";
dirs[i++] = "perl5";
dirs[i++] = "personal";
dirs[i++] = "pforum";
dirs[i++] = "phorum";
dirs[i++] = "php";
dirs[i] = "phpBB";		exec[i++] = 1;
dirs[i] = "phpMyAdmin";		exec[i++] = 1;
dirs[i] = "phpPhotoAlbum";	exec[i++] = 1;
dirs[i] = "phpSecurePages";	exec[i++] = 1;
dirs[i] = "php_classes";	exec[i++] = 1;
dirs[i] = "phpclassifieds";	exec[i++] = 1;
dirs[i] = "phpimageview";	exec[i++] = 1;
dirs[i] = "phpnuke";		exec[i++] = 1;
dirs[i] = "phpprojekt";		exec[i++] = 1;
dirs[i++] = "piranha";
dirs[i++] = "pls";
dirs[i++] = "poll";
dirs[i++] = "polls";
dirs[i++] = "postgres";
dirs[i++] = "ppwb";
dirs[i++] = "printers";
dirs[i++] = "priv";
dirs[i++] = "privado";
dirs[i] = "private";		score[i++] = 1;
dirs[i++] = "prod";
dirs[i] = "protected";		score[i++] = 1;
dirs[i++] = "prueba";
dirs[i++] = "pruebas";
dirs[i++] = "prv";
dirs[i++] = "pub";
dirs[i++] = "public";
dirs[i++] = "publica";
dirs[i++] = "publicar";
dirs[i++] = "publico";
dirs[i++] = "publish";
dirs[i++] = "purchase";
dirs[i++] = "purchases";
dirs[i++] = "pw";
dirs[i++] = "random_banner";
dirs[i++] = "rdp";
dirs[i++] = "register";
dirs[i++] = "registered";
dirs[i++] = "report";
dirs[i++] = "reports";
dirs[i++] = "reseller";
dirs[i++] = "restricted";
dirs[i++] = "retail";
dirs[i++] = "reviews";
dirs[i++] = "root";
dirs[i++] = "rsrc";
dirs[i++] = "sales";
dirs[i++] = "sample";
dirs[i++] = "samples";
dirs[i++] = "save";
dirs[i++] = "script";
dirs[i] = "scripts";		exec[i++] = 1;
dirs[i++] = "search";
dirs[i++] = "search-ui";
dirs[i] = "secret";		score[i++] = 1;
dirs[i] = "secure";		score[i++] = 1;
dirs[i] = "secured";		score[i++] = 1;
dirs[i++] = "sell";
dirs[i++] = "server-info";
dirs[i++] = "server-status";
dirs[i++] = "server_stats";
dirs[i++] = "servers";
dirs[i++] = "serverstats";
dirs[i++] = "service";
dirs[i++] = "services";
dirs[i++] = "servicio";
dirs[i++] = "servicios";
dirs[i++] = "servlet";
dirs[i++] = "servlets";
dirs[i++] = "session";
dirs[i++] = "setup";
dirs[i++] = "share";
dirs[i++] = "shared";
dirs[i++] = "shell-cgi";
dirs[i++] = "shipping";
dirs[i++] = "shop";
dirs[i++] = "shopper";
dirs[i++] = "site";
dirs[i] = "siteadmin";		score[i++] = 1;
dirs[i++] = "sitemgr";
dirs[i++] = "siteminder";
dirs[i++] = "siteminderagent";
dirs[i] = "sites";		score[i++] = 1;
dirs[i++] = "siteserver";
dirs[i++] = "sitestats";
dirs[i++] = "siteupdate";
dirs[i++] = "smreports";
dirs[i++] = "smreportsviewer";
dirs[i++] = "soap";
dirs[i++] = "soapdocs";
dirs[i++] = "software";
dirs[i++] = "solaris";
dirs[i++] = "source";
dirs[i++] = "sql";
dirs[i++] = "squid";
dirs[i++] = "src";
dirs[i++] = "srchadm";
dirs[i] = "ssi";		score[i++] = 1;
dirs[i] = "ssl";		score[i++] = 1;
dirs[i] = "sslkeys";		score[i++] = 1;
dirs[i++] = "staff";
dirs[i] = "stat";		score[i++] = 1;
dirs[i] = "statistic";		score[i++] = 1;
dirs[i] = "statistics";		score[i++] = 1;
dirs[i] = "stats";		score[i++] = 1;
dirs[i++] = "stats-bin-p";
dirs[i] = "stats_old";		score[i++] = 1;
dirs[i++] = "status";
dirs[i++] = "storage";
dirs[i++] = "store";
dirs[i++] = "storemgr";
dirs[i++] = "stronghold-info";
dirs[i++] = "stronghold-status";
dirs[i++] = "stuff";
dirs[i++] = "style";
dirs[i++] = "styles";
dirs[i++] = "stylesheet";
dirs[i++] = "stylesheets";
dirs[i++] = "subir";
dirs[i++] = "sun";
dirs[i++] = "super_stats";
dirs[i++] = "support";
dirs[i++] = "supporter";
dirs[i] = "sys";		score[i++] = 1;
dirs[i] = "sysadmin";		score[i++] = 1;
dirs[i] = "sysbackup";		score[i++] = 1;
dirs[i++] = "system";
dirs[i++] = "tar";
dirs[i++] = "tarjetas";
dirs[i++] = "te_html";
dirs[i++] = "tech";
dirs[i++] = "technote";
dirs[i++] = "temp";
dirs[i++] = "template";
dirs[i++] = "templates";
dirs[i++] = "temporal";
dirs[i] = "test";		score[i++] = 1;
dirs[i++] = "test-cgi";
dirs[i] = "testing";	 	score[i++] = 1;
dirs[i] = "tests";		score[i++] = 1;
dirs[i++] = "testweb";
dirs[i++] = "ticket";
dirs[i++] = "tickets";
dirs[i] = "tmp";		score[i++] = 1;
dirs[i++] = "tools";
dirs[i++] = "tpv";
dirs[i++] = "trabajo";
dirs[i++] = "transito";
dirs[i++] = "transpolar";
dirs[i++] = "tree";
dirs[i++] = "trees";
dirs[i++] = "updates";
dirs[i++] = "upload";
dirs[i++] = "uploads";
dirs[i++] = "us";
dirs[i++] = "usage";
dirs[i++] = "user";
dirs[i] = "userdb";		score[i++] = 1;
dirs[i] = "users";		score[i++] = 1;
dirs[i++] = "usr";
dirs[i] = "ustats";		score[i++] = 1;
dirs[i++] = "usuario";
dirs[i++] = "usuarios";
dirs[i++] = "util";
dirs[i++] = "utils";
dirs[i++] = "vfs";
dirs[i++] = "w-agora";
dirs[i++] = "w3perl";
dirs[i++] = "way-board";
dirs[i++] = "web";
dirs[i++] = "web800fo";
dirs[i++] = "webdav";
dirs[i++] = "webMathematica";
dirs[i] = "web_usage";		score[i++] = 1;
dirs[i] = "webaccess";		score[i++] = 1;
dirs[i] = "webadmin";		score[i++] = 1;
dirs[i] = "webalizer";		score[i++] = 1;
dirs[i++] = "webapps";
dirs[i++] = "webboard";
dirs[i++] = "webcart";
dirs[i++] = "webcart-lite";
dirs[i++] = "webdata";
dirs[i++] = "webdb";
dirs[i++] = "webimages";
dirs[i++] = "webimages2";
dirs[i++] = "weblog";
dirs[i++] = "weblogs";
dirs[i++] = "webmaster";
dirs[i++] = "webmaster_logs";
dirs[i++] = "webpub";
dirs[i++] = "webpub-ui";
dirs[i++] = "webreports";
dirs[i++] = "webreps";
dirs[i++] = "webshare";
dirs[i++] = "website";
dirs[i] = "webstat";		score[i++] = 1;
dirs[i] = "webstats";		score[i++] = 1;
dirs[i++] = "webtrace";
dirs[i] = "webtrends";		score[i++] = 1;
dirs[i++] = "windows";
dirs[i++] = "word";
dirs[i++] = "work";
dirs[i++] = "wsdocs";
dirs[i] = "wstats";		score[i++] = 1;
dirs[i] = "wusage";		score[i++] = 1;
dirs[i++] = "www";
dirs[i++] = "www-sql";
dirs[i++] = "wwwjoin";
dirs[i] = "wwwlog";		score[i++] = 1;
dirs[i] = "wwwstat";		score[i++] = 1;
dirs[i] = "wwwstats";		score[i++] = 1;
dirs[i++] = "xGB";
dirs[i++] = "xml";
dirs[i++] = "xtemp";
dirs[i++] = "zb41";
dirs[i++] = "zipfiles";
dirs[i++] = "~1";
dirs[i] = "~admin";		score[i++] = 1;
dirs[i++] = "~log";
dirs[i++] = "~root";
dirs[i] = "~stats";		score[i++] = 1;
dirs[i] = "~webstats";		score[i++] = 1;
dirs[i++] = "~wsdocs";
dirs[i++] = "track";
dirs[i++] = "tracking";
dirs[i++] = "BizTalkTracking";
dirs[i++] = "BizTalkServerDocs";
dirs[i++] = "BizTalkServerRepository";
dirs[i++] = "MessagingManager";
dirs[i++] = "iisprotect";
dirs[i] = "mp3";		score[i++] = 1;
dirs[i] = "mp3s";		score[i++] = 1;
dirs[i++] = "acid";
dirs[i++] = "chat";
dirs[i++] = "eManager";
dirs[i++] = "keyserver";
dirs[i++] = "search97";
dirs[i++] = "tarantella";
dirs[i++] = "webmail";
dirs[i++] = "flexcube@";
dirs[i++] = "flexcubeat";
dirs[i++] = "ganglia";
dirs[i++] = "sitebuildercontent";
dirs[i++] = "sitebuilderfiles";
dirs[i++] = "sitebuilderpictures";
dirs[i++] = "WSsamples";
dirs[i++] = "mercuryboard";
dirs[i++] = "tdbin";
dirs[i++] = "AlbumArt_";
# The three following directories exist on Resin default installation
dirs[i++] = "faq";
dirs[i++] = "ref";
dirs[i++] = "cmp";
# Phishing
dirs[i] = "cgi-bim";		exec[i++] = 1;
# Lite-serve
dirs[i] = "cgi-isapi";		exec[i++] = 1;
# HyperWave
dirs[i++] = "wavemaster.internal";
# Urchin
dirs[i++] = "urchin";
dirs[i++] = "urchin3";
dirs[i++] = "urchin5";
# CVE-2000-0237
dirs[i++] = "publisher";
# Common Locale
dirs[i++] = "en";
dirs[i++] = "en-US";
dirs[i++] = "fr";
dirs[i++] = "intl";
# Seen on Internet
dirs[i++] = "about";
dirs[i++] = "aspx";
dirs[i++] = "Boutiques";
dirs[i++] = "business";
dirs[i++] = "content";
dirs[i++] = "Corporate";
dirs[i++] = "company";
dirs[i++] = "client";
dirs[i++] = "DB4Web";
dirs[i] = "dll";		exec[i++] = 1;
dirs[i++] = "frameset";
dirs[i++] = "howto";
dirs[i++] = "legal";
dirs[i++] = "member";
dirs[i++] = "myaccount";
dirs[i++] = "obj";
dirs[i++] = "offers";
dirs[i++] = "personal_pages";
dirs[i++] = "rem";
dirs[i++] = "Remote";
dirs[i++] = "serve";
dirs[i++] = "shopping";
dirs[i++] = "slide";
dirs[i++] = "solutions";
dirs[i++] = "v4";
dirs[i++] = "wws";		# Sympa
dirs[i++] = "squirrelmail";
dirs[i++] = "dspam";
dirs[i++] = "cacti";

# Add domain name parts
hn = get_host_name();
if( ! ereg( string:hn, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" ) ) {

  hnp = split( hn, sep:"." );
  foreach p( hnp ) {
    n = max_index( dirs );
    #TBD: The following looks broken...
    for( j = 0; j < n && dirs[j] != p; j++ )
     ;
      if( j < n ) dirs[n] = p;
  }
}

# this needs to be updated to match the above list
dirs_last = i - 1;

debug = 0;

if( debug ) display( "::[ DDI Directory Scanner running in debug mode\n::\n" );

fake404 = string("");
Check200 = 1;
Check401 = 1;
Check403 = 1;

# this arrays contains the results
discovered[0] = 0;
discovered_last = 0;
authDir[0] = 0;
authDir_last = 0;

cgi_dirs_exclude_pattern = get_kb_item( "Settings/cgi_dirs_exclude_pattern" );
use_cgi_dirs_exclude_pattern = get_kb_item( "Settings/use_cgi_dirs_exclude_pattern" );

port = get_http_port( default:80 );

if( get_kb_item( "Services/www/" + port + "/embedded" ) ) exit( 0 );

#counter for current failed requests
failedReqs = 0;
#counter for max failed requests
#The NVT will exit if this is reached
#TBD: Make this configurable?
maxFailedReqs = 3;

##
# pull the robots.txt file
##

if( debug ) display( ":: Checking for robots.txt...\n" );

req = http_get( item:"/robots.txt", port:port );
http_data = http_keepalive_send_recv( port:port, data:req );

if( http_data == NULL ) failedReqs++;

if( ereg( pattern:"^HTTP/1.[01] 200 ", string:http_data ) ) {

  strings = split( http_data );

  foreach string( strings ) {

    if( egrep( pattern:"(dis)?allow:.*/", string:string, icase:TRUE ) &&
        ! egrep( pattern:"(dis)?allow:.*\.", string:string, icase:TRUE ) ) {

      # yes, i suck at regex's in nasl. I want my \s+!
      robot_dir = ereg_replace( pattern:"(dis)?allow:\W*/(.*)$", string:string, replace:"\2", icase:TRUE );
      robot_dir = ereg_replace( pattern:"\W*$", string:robot_dir, replace:"", icase:TRUE );
      robot_dir = ereg_replace( pattern:"/$|\?$", string:robot_dir, replace:"", icase:TRUE );

      if( ! check_dir_list( dir:robot_dir ) && robot_dir != '' ) {
        # add directory to the list
        dirs_last = dirs_last + 1;
        dirs[dirs_last] = robot_dir;
        if( debug ) display(":: Directory '", robot_dir, "' added to test list\n");
      } else {
        if( debug ) display( ":: Directory '", robot_dir, "' already exists in test list\n" );
      }
    }
  }
}

##
# pull the CVS/Entries file
##

if( debug ) display( ":: Checking for /CVS/Entries...\n" );

req = http_get( item:"/CVS/Entries", port:port );
http_data = http_keepalive_send_recv( port:port, data:req );

if( http_data == NULL ) failedReqs++;

if( ereg( pattern:"^HTTP/1.[01] 200 ", string:http_data ) ) {

  strings = split(http_data, string("\n"));

  foreach string( strings ) {

    if( ereg( pattern:"^D/(.*)////", string:string, icase:TRUE ) ) {

      cvs_dir = ereg_replace( pattern:"D/(.*)////.*", string:string, replace:"\1", icase:TRUE );

      if( ! check_dir_list( dir:cvs_dir ) ) {
        # add directory to the list
        dirs_last = dirs_last + 1;
        dirs[dirs_last] = cvs_dir;
        if( debug ) display( ":: Directory '", cvs_dir, "' added to test list\n" );
      } else {
        if( debug ) display( ":: Directory '", cvs_dir, "' already exists in test list\n" );
      }
    }
  }
}

##
# test for servers which return 200/403/401 for everything
##

req = http_get( item:"/NonExistant" + rand() + "/", port:port );
http_resp = http_keepalive_send_recv( port:port, data:req );

if( http_resp == NULL ) failedReqs++;

if( ereg( pattern:"^HTTP/1.[01] 200 ", string:http_resp ) ) {

  fake404 = 0;

  if( debug ) display( ":: This server returns 200 for non-existent directories.\n" );

  foreach errmsg( errmessages_404 ) {
    if( egrep( pattern:errmsg, string:http_resp, icase:TRUE ) && ! fake404 ) {
      fake404 = errmsg;
      if( debug ) display( ":: Using '", fake404, "' as an indication of a 404 error\n" );
    }
  }

  if( ! fake404 ) {

    if( debug ) display( ":: Could not find an error string to match against for the fake 404 response.\n" );
    if( debug ) display( ":: Checks which rely on 200 responses are being disabled\n" );

    Check200 = 0;
  }
} else {
  fake404 = string( "BadString0987654321*DDI*" );
}

if( ereg( pattern:"^HTTP/1.[01] 401 ", string: http_resp ) ) {
  if( debug ) display( ":: This server requires authentication for non-existent directories, disabling 401 checks.\n" );
  Check401 = 0;
}

if( ereg( pattern:"^HTTP/1.[01] 403 ", string: http_resp ) ) {
  if( debug ) display( ":: This server returns a 403 for non-existent directories, disabling 403 checks.\n" );
  Check403 = 0;
}

##
# start the actual directory scan
##

ScanRootDir = "/";

# copy the directory test list
cdirs[0] = 0;
for( dcp = 0; dirs[dcp]; dcp++ ) {
  cdirs[dcp] = dirs[dcp];
  cdirs_last = dcp;
}

for( pass = 0; pass < 2; pass++ ) {

  start_pass = unixtime();
  if( debug ) display( ":: Starting the directory scan...\n" );

  for( i = 0; cdirs[i]; i++ ) {

    if( pass == 0 && score[i] == 0 ) continue;
    if( pass == 1 && score[i] != 0 ) continue;

    req = http_get( item:ScanRootDir + cdirs[i] + "/", port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res == NULL ) {
      failedReqs++;
      if( failedReqs >= maxFailedReqs ) {
        if( debug ) display( ":: Max number of failed requests (" + maxFailedReqs + ") reached, exiting...\n" );
        exit( 0 );
      }
      continue;
    }

    http_code = int( substr( res, 9, 11 ) );
    if( ! res ) res = "BogusBogusBogus";

    if( Check200 && http_code == 200 && ! ( egrep( pattern:fake404, string:res, icase:TRUE ) ) ) {

      if( debug ) display( ":: Discovered: " , ScanRootDir, cdirs[i], "\n" );

      add_discovered_list( dir:ScanRootDir + cdirs[i] );
      if( exec[i] != 0 ) {
        if( check_cgi_dir( dir:cdirs[i] ) ) CGI_Dirs = make_list( CGI_Dirs, cdirs[i] );
      }
    }

    if( Check403 && http_code == 403 ) {

      if( debug ) display( ":: Got a 403 for ", ScanRootDir, cdirs[i], ", checking for file in the directory...\n" );

      soc = check_req_send( port:port, url:ScanRootDir + cdirs[i] + "/NonExistent.html" );
      res2 = check_req_recv( soc:soc );

      if( ereg( pattern:"^HTTP/1.[01] 403 ", string:res2 ) ) {
        # the whole directory appears to be protected
        if( debug ) display( "::   403 applies to the entire directory \n" );
      } else {
        if( debug ) display( "::   403 applies to just directory indexes \n" );

        # the directory just has indexes turned off
        if( debug ) display( ":: Discovered: " , ScanRootDir, cdirs[i], "\n" );
        add_discovered_list( dir:ScanRootDir + cdirs[i] );
        if( exec[i] != 0 ) CGI_Dirs = make_list( CGI_Dirs, cdirs[i] );
      }
    }

    if( Check401 && http_code == 401 ) {

      if( debug ) display( ":: Got a 401 for ", ScanRootDir + cdirs[i], "\n" );
      add_auth_dir_list( dir:ScanRootDir + cdirs[i] );
    }
  }
  if( pass == 0 && unixtime() - start_pass > 80 ) break;
}

exit( 0 );
