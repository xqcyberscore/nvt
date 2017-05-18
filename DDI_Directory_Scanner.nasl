###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_Directory_Scanner.nasl 5907 2017-04-10 07:09:24Z cfi $
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
  script_version("$Revision: 5907 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-10 09:09:24 +0200 (Mon, 10 Apr 2017) $");
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
include("misc_func.inc");

function check_cgi_dir( dir, port ) {

  local_var req, res, dir, port;

  req = http_get( item:dir + "/non-existent"  + rand(), port:port );
  res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );
  if( isnull( res ) ) failedReqs++;

  if( res =~ "^HTTP/1\.[01] 404" ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

function add_discovered_list( dir, port ) {

  local_var dir, port, dir_key;

  if( ! in_array( search:dir, array:discoveredDirList ) ) {
    discoveredDirList = make_list( discoveredDirList, dir );

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    #TBD: Do a check_cgi_dir( dir:dir, port:port ); before?
    dir_key = "www/" + port + "/content/directories";
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir, "'\n" );
    set_kb_item( name:dir_key, value:dir );
  }
}

function add_auth_dir_list( dir, port ) {

  local_var dir, port, dir_key;

  if( ! in_array( search:dir, array:authDirList ) ) {
    authDirList = make_list( authDirList, dir );

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

# TODO: Update list with directories
testDirList = make_list(
".cobalt",
"1",
"10",
"2",
"3",
"4",
"5",
"6",
"7",
"8",
"9",
"AdminWeb",
"Admin_files",
"Administration",
"AdvWebAdmin",
"Agent",
"Agents",
"Album",
"CS",
"CVS",
"DMR",
"DocuColor",
"GXApp",
"HB",
"HBTemplates",
"IBMWebAS",
"Install",
"JBookIt",
"Log",
"Mail",
"Msword",
"NSearch",
"NetDynamic",
"NetDynamics",
"News",
"PDG_Cart",
"README",
"ROADS",
"Readme",
"SilverStream",
"Stats",
"StoreDB",
"Templates",
"ToDo",
"WebBank",
"WebCalendar",
"WebDB",
"WebShop",
"WebTrend",
"Web_store",
"XSL",
"_ScriptLibrary",
"_backup",
"_derived",
"_errors",
"_fpclass",
"_mem_bin",
"_notes",
"_objects",
"_old",
"_pages",
"_passwords",
"_private",
"_scripts",
"_sharedtemplates",
"_tests",
"_themes",
"_vti_bin",
"_vti_bot",
"_vti_log",
"_vti_pvt",
"_vti_shm",
"_vti_txt",
"a",
"acceso",
"access",
"accesswatch",
"acciones",
"account",
"accounting",
"activex",
"adm",
"admcgi",
"admentor",
"admin",
"admin-bak",
"admin-old",
"admin.back",
"admin_",
"administration",
"administrator",
"adminuser",
"adminweb",
"admisapi",
"agentes",
"analog",
"anthill",
"apache",
"app",
"applets",
"application",
"applications",
"apps",
"ar",
"archive",
"archives",
"asp",
"atc",
"auth",
"authadmin",
"aw",
"ayuda",
"b",
"b2-include",
"back",
"backend",
"backup",
"backups",
"bak",
"banca",
"banco",
"bank",
"banner",
"banner01",
"banners",
"batch",
"bb-dnbd",
"bbv",
"bdata",
"bdatos",
"beta",
"billpay",
"bin",
"boadmin",
"boot",
"btauxdir",
"bug",
"bugs",
"bugzilla",
"buy",
"buynow",
"c",
"cache-stats",
"caja",
"card",
"cards",
"cart",
"cash",
"caspsamp",
"catalog",
"cbi-bin",
"ccard",
"ccards",
"cd",
"cd-cgi",
"cdrom",
"ce_html",
"cert",
"certificado",
"certificate",
"cfappman",
"cfdocs",
"cfide",
"cgi",
"cgi-auth",
"cgi-bin",
"cgi-bin2",
"cgi-csc",
"cgi-lib",
"cgi-local",
"cgi-scripts",
"cgi-shl",
"cgi-shop",
"cgi-sys",
"cgi-weddico",
"cgi-win",
"cgibin",
"cgilib",
"cgis",
"cgiscripts",
"cgiwin",
"class",
"classes",
"cliente",
"clientes",
"cm",
"cmsample",
"cobalt-images",
"code",
"comments",
"common",
"communicator",
"compra",
"compras",
"compressed",
"conecta",
"conf",
"config",
"connect",
"console",
"controlpanel",
"core",
"corp",
"correo",
"counter",
"credit",
"cron",
"crons",
"crypto",
"csr",
"css",
"cuenta",
"cuentas",
"currency",
"customers",
"cvsweb",
"cybercash",
"d",
"darkportal",
"dat",
"dav",
"data",
"database",
"databases",
"datafiles",
"dato",
"datos",
"db",
"dbase",
"dcforum",
"ddreport",
"ddrint",
"demo",
"demoauct",
"demomall",
"demos",
"design",
"dev",
"devel",
"development",
"dir",
"directory",
"directorymanager",
"dl",
"dm",
"dms",
"dms0",
"dmsdump",
"doc",
"doc-html",
"doc1",
"docs",
"docs1",
"document",
"documents",
"down",
"download",
"downloads",
"dump",
"durep",
"e",
"easylog",
"eforum",
"ejemplo",
"ejemplos",
"email",
"emailclass",
"employees",
"empoyees",
"empris",
"envia",
"enviamail",
"error",
"errors",
"es",
"estmt",
"etc",
"example",
"examples",
"exc",
"excel",
"exchange",
"exe",
"exec",
"export",
"external",
"f",
"fbsd",
"fcgi-bin",
"file",
"filemanager",
"files",
"foldoc",
"form",
"form-totaller",
"forms",
"formsmgr",
"forum",
"forums",
"foto",
"fotos",
"fpadmin",
"fpdb",
"fpsample",
"framesets",
"ftp",
"ftproot",
"g",
"gfx",
"global",
"grocery",
"guest",
"guestbook",
"guests",
"help",
"helpdesk",
"hidden",
"hide",
"hit_tracker",
"hitmatic",
"hlstats",
"home",
"hostingcontroller",
"ht",
"htbin",
"htdocs",
"html",
"hyperstat",
"ibank",
"ibill",
"icons",
"idea",
"ideas",
"iisadmin",
"iissamples",
"image",
"imagenes",
"imagery",
"images",
"img",
"imp",
"import",
"impreso",
"inc",
"include",
"includes",
"incoming",
"info",
"information",
"ingresa",
"ingreso",
"install",
"internal",
"intranet",
"inventory",
"invitado",
"isapi",
"japidoc",
"java",
"javascript",
"javasdk",
"javatest",
"jave",
"jdbc",
"job",
"jrun",
"js",
"jserv",
"jslib",
"jsp",
"junk",
"kiva",
"labs",
"lcgi",
"lib",
"libraries",
"library",
"libro",
"links",
"linux",
"loader",
"log",
"logfile",
"logfiles",
"logg",
"logger",
"logging",
"login",
"logon",
"logs",
"lost+found",
"mail",
"mail_log_files",
"mailman",
"mailroot",
"makefile",
"mall_log_files",
"manage",
"manual",
"marketing",
"members",
"message",
"messaging",
"metacart",
"misc",
"mkstats",
"movimientos",
"mqseries",
"msql",
"mysql",
"mysql_admin",
"ncadmin",
"nchelp",
"ncsample",
"netbasic",
"netcat",
"netmagstats",
"netscape",
"netshare",
"nettracker",
"new",
"nextgeneration",
"nl",
"noticias",
"objects",
"odbc",
"old",
"old_files",
"oldfiles",
"oprocmgr-service",
"oprocmgr-status",
"oracle",
"oradata",
"order",
"orders",
"outgoing",
"owners",
"pages",
"passport",
"password",
"passwords",
"payment",
"payments",
"pccsmysqladm",
"perl",
"perl5",
"personal",
"pforum",
"phorum",
"php",
"phpBB",
"phpMyAdmin",
"phpPhotoAlbum",
"phpSecurePages",
"php_classes",
"phpclassifieds",
"phpimageview",
"phpnuke",
"phpprojekt",
"piranha",
"pls",
"poll",
"polls",
"postgres",
"ppwb",
"printers",
"priv",
"privado",
"private",
"prod",
"protected",
"prueba",
"pruebas",
"prv",
"pub",
"public",
"publica",
"publicar",
"publico",
"publish",
"purchase",
"purchases",
"pw",
"random_banner",
"rdp",
"register",
"registered",
"report",
"reports",
"reseller",
"restricted",
"retail",
"reviews",
"root",
"rsrc",
"sales",
"sample",
"samples",
"save",
"script",
"scripts",
"search",
"search-ui",
"secret",
"secure",
"secured",
"sell",
"server-info",
"server-status",
"server_stats",
"servers",
"serverstats",
"service",
"services",
"servicio",
"servicios",
"servlet",
"servlets",
"session",
"setup",
"share",
"shared",
"shell-cgi",
"shipping",
"shop",
"shopper",
"site",
"siteadmin",
"sitemgr",
"siteminder",
"siteminderagent",
"sites",
"siteserver",
"sitestats",
"siteupdate",
"smreports",
"smreportsviewer",
"soap",
"soapdocs",
"software",
"solaris",
"source",
"sql",
"squid",
"src",
"srchadm",
"ssi",
"ssl",
"sslkeys",
"staff",
"stat",
"statistic",
"statistics",
"stats",
"stats-bin-p",
"stats_old",
"status",
"storage",
"store",
"storemgr",
"stronghold-info",
"stronghold-status",
"stuff",
"style",
"styles",
"stylesheet",
"stylesheets",
"subir",
"sun",
"super_stats",
"support",
"supporter",
"sys",
"sysadmin",
"sysbackup",
"system",
"tar",
"tarjetas",
"te_html",
"tech",
"technote",
"temp",
"template",
"templates",
"temporal",
"test",
"test-cgi",
"testing",
"tests",
"testweb",
"ticket",
"tickets",
"tmp",
"tools",
"tpv",
"trabajo",
"transito",
"transpolar",
"tree",
"trees",
"updates",
"upload",
"uploads",
"us",
"usage",
"user",
"userdb",
"users",
"usr",
"ustats",
"usuario",
"usuarios",
"util",
"utils",
"vfs",
"w-agora",
"w3perl",
"way-board",
"web",
"web800fo",
"webdav",
"webMathematica",
"web_usage",
"webaccess",
"webadmin",
"webalizer",
"webapps",
"webboard",
"webcart",
"webcart-lite",
"webdata",
"webdb",
"webimages",
"webimages2",
"weblog",
"weblogs",
"webmaster",
"webmaster_logs",
"webpub",
"webpub-ui",
"webreports",
"webreps",
"webshare",
"website",
"webstat",
"webstats",
"webtrace",
"webtrends",
"windows",
"word",
"work",
"wsdocs",
"wstats",
"wusage",
"www",
"www-sql",
"wwwjoin",
"wwwlog",
"wwwstat",
"wwwstats",
"xGB",
"xml",
"xtemp",
"zb41",
"zipfiles",
"~1",
"~admin",
"~log",
"~root",
"~stats",
"~webstats",
"~wsdocs",
"track",
"tracking",
"BizTalkTracking",
"BizTalkServerDocs",
"BizTalkServerRepository",
"MessagingManager",
"iisprotect",
"mp3",
"mp3s",
"acid",
"chat",
"eManager",
"keyserver",
"search97",
"tarantella",
"webmail",
"flexcube@",
"flexcubeat",
"ganglia",
"sitebuildercontent",
"sitebuilderfiles",
"sitebuilderpictures",
"WSsamples",
"mercuryboard",
"tdbin",
"AlbumArt_",
# The three following directories exist on Resin default installation
"faq",
"ref",
"cmp",
# Phishing
"cgi-bim",
# Lite-serve
"cgi-isapi",
# HyperWave
"wavemaster.internal",
# Urchin
"urchin",
"urchin3",
"urchin5",
# CVE-2000-0237
"publisher",
# Common Locale
"en",
"en-US",
"fr",
"intl",
# Seen on Internet
"about",
"aspx",
"Boutiques",
"business",
"content",
"Corporate",
"company",
"client",
"DB4Web",
"dll",
"frameset",
"howto",
"legal",
"member",
"myaccount",
"obj",
"offers",
"personal_pages",
"rem",
"Remote",
"serve",
"shopping",
"slide",
"solutions",
"v4",
# Sympa
"wws",
"squirrelmail",
"dspam",
"cacti",
"alt",
"wiki",
"phpmyadmin",
"pma",
"roundcube",
"roundcubemail",
"board",
"community",
# Tomcat
"manager/html",
"host-manager/html",
"manager/status" );

# Add domain name parts
hn = get_host_name();
if( ! ereg( string:hn, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" ) ) {
  hnp = split( hn, sep:".", keep:FALSE );
  foreach p( hnp ) {
    if( ! in_array( search:p, array:testDirList ) ) testDirList = make_list( testDirList, p );
  }
}

debug = 0;

if( debug ) display( "::[ DDI Directory Scanner running in debug mode\n::\n" );

fake404 = string("");
Check200 = TRUE;
Check401 = TRUE;
Check403 = TRUE;

# this arrays contains the results
discoveredDirList = make_list();
authDirList = make_list();

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
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  strings = split( res );

  foreach string( strings ) {

    if( egrep( pattern:"(dis)?allow:.*/", string:string, icase:TRUE ) &&
        ! egrep( pattern:"(dis)?allow:.*\.", string:string, icase:TRUE ) ) {

      # yes, i suck at regex's in nasl. I want my \s+!
      robot_dir = ereg_replace( pattern:"(dis)?allow:\W*/(.*)$", string:string, replace:"\2", icase:TRUE );
      robot_dir = ereg_replace( pattern:"\W*$", string:robot_dir, replace:"", icase:TRUE );
      robot_dir = ereg_replace( pattern:"/$|\?$", string:robot_dir, replace:"", icase:TRUE );

      if( robot_dir != '' && ! in_array( search:robot_dir, array:testDirList ) ) {
        # add directory to the list
        testDirList = make_list( testDirList, robot_dir );
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
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  strings = split( res, string( "\n" ) );

  foreach string( strings ) {

    if( ereg( pattern:"^D/(.*)////", string:string, icase:TRUE ) ) {

      cvs_dir = ereg_replace( pattern:"D/(.*)////.*", string:string, replace:"\1", icase:TRUE );

      if( ! in_array( search:cvs_dir, array:testDirList ) ) {
        # add directory to the list
        testDirList = make_list( testDirList, cvs_dir );
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
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  fake404 = 0;

  if( debug ) display( ":: This server returns 200 for non-existent directories.\n" );

  foreach errmsg( errmessages_404 ) {
    if( egrep( pattern:errmsg, string:res, icase:TRUE ) && ! fake404 ) {
      fake404 = errmsg;
      if( debug ) display( ":: Using '", fake404, "' as an indication of a 404 error\n" );
      break;
    }
  }

  if( ! fake404 ) {

    if( debug ) display( ":: Could not find an error string to match against for the fake 404 response.\n" );
    if( debug ) display( ":: Checks which rely on 200 responses are being disabled\n" );

    Check200 = FALSE;
  }
} else {
  fake404 = string( "BadString0987654321*DDI*" );
}

if( res =~ "^HTTP/1\.[01] 401" ) {
  if( debug ) display( ":: This server requires authentication for non-existent directories, disabling 401 checks.\n" );
  Check401 = FALSE;
}

if( res =~ "^HTTP/1\.[01] 403" ) {
  if( debug ) display( ":: This server returns a 403 for non-existent directories, disabling 403 checks.\n" );
  Check403 = FALSE;
}

##
# start the actual directory scan
##

ScanRootDir = "/";

start = unixtime();
if( debug ) display( ":: Starting the directory scan...\n" );

foreach cdir( testDirList ) {

  res = http_get_cache( item:ScanRootDir + cdir + "/", port:port );

  if( isnull( res ) ) {
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

    if( debug ) display( ":: Discovered: " , ScanRootDir, cdir, "\n" );

    add_discovered_list( dir:ScanRootDir + cdir, port:port );
  }

  if( Check403 && http_code == 403 ) {

    if( debug ) display( ":: Got a 403 for ", ScanRootDir, cdir, ", checking for file in the directory...\n" );

    req = http_get( item:ScanRootDir + cdir + "/NonExistent.html", port:port );
    res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );

    if( res =~ "^HTTP/1\.[01] 403" ) {
      # the whole directory appears to be protected
      if( debug ) display( "::   403 applies to the entire directory \n" );
    } else {
      if( debug ) display( "::   403 applies to just directory indexes \n" );

      # the directory just has indexes turned off
      if( debug ) display( ":: Discovered: " , ScanRootDir, cdir, "\n" );
      add_discovered_list( dir:ScanRootDir + cdir, port:port );
    }
  }

  if( Check401 && http_code == 401 ) {

    if( debug ) display( ":: Got a 401 for ", ScanRootDir + cdir, "\n" );
    add_auth_dir_list( dir:ScanRootDir + cdir, port:port );
  }
  #TBD: Make this configureable?
  if( unixtime() - start > 80 ) exit( 0 );
}

exit( 0 );
