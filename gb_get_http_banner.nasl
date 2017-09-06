###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_get_http_banner.nasl 7056 2017-09-05 04:41:55Z ckuersteiner $
#
# HTTP Banner
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.140170");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 7056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-05 06:41:55 +0200 (Tue, 05 Sep 2017) $");
 script_tag(name:"creation_date", value:"2017-02-21 11:53:19 +0100 (Tue, 21 Feb 2017)");
 script_name("HTTP Banner");

 script_tag(name: "summary" , value: "This script get the HTTP banner and store some values in the KB related to this banner.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

function set_mandatory_key( key, regex )
{
  local_var key, regex;

  if( ! key )   return;
  if( ! regex ) return;

  if( m = egrep( pattern:regex, string:banner, icase:TRUE ) )
    replace_kb_item( name:key + '/banner', value:TRUE );

  return;

}

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

set_mandatory_key( key:"uc_httpd", regex:"Server: uc-httpd");
set_mandatory_key( key:"MyServer", regex:"MyServer ([0-9.]+)");
set_mandatory_key( key:"Ipswitch", regex:"Server: Ipswitch");
set_mandatory_key( key:"EasyFileSharingWebServer", regex:"Server: Easy File Sharing Web Server");
set_mandatory_key( key:"Abyss", regex:"Abyss/");
set_mandatory_key( key:"Sun-Java-System-Web-Proxy-Server", regex:"Server: Sun-Java-System-Web-Proxy-Server/");
set_mandatory_key( key:"IBM_HTTP_Server", regex:"Server: IBM_HTTP_Server");
set_mandatory_key( key:"GoAhead-Webs", regex:"Server: GoAhead");
set_mandatory_key( key:"zope", regex:"Zope ([0-9.]+)");
set_mandatory_key( key:"ELOG_HTTP", regex:"Server: ELOG HTTP");
set_mandatory_key( key:"dwhttpd", regex:"dwhttpd");
set_mandatory_key( key:"Zervit", regex:"Server: Zervit ([0-9.]+)");
set_mandatory_key( key:"apache", regex:"Server: Apache/");
set_mandatory_key( key:"CommuniGatePro", regex:"Server: CommuniGatePro/");
set_mandatory_key( key:"WinGate", regex:"WinGate");
set_mandatory_key( key:"thin", regex:"Server: thin");
set_mandatory_key( key:"Cherokee", regex:"Cherokee");
set_mandatory_key( key:"corehttp", regex:"Server: corehttp");
set_mandatory_key( key:"RaidenHTTPD", regex:"Server: RaidenHTTPD/([0-9.]+)");
set_mandatory_key( key:"InterVations", regex:"Server:.*InterVations");
set_mandatory_key( key:"Monkey", regex:"Server: Monkey/");
set_mandatory_key( key:"Savant", regex:"Server: Savant/");
set_mandatory_key( key:"Jetty", regex:"Server: Jetty");
set_mandatory_key( key:"Polipo", regex:"Server: Polipo");
set_mandatory_key( key:"iWeb", regex:"Server: iWeb");
set_mandatory_key( key:"HWS", regex:"Server: .*\(HWS[0-9]+\)");
set_mandatory_key( key:"Serv-U", regex:"Server: Serv-U/");
set_mandatory_key( key:"uhttps", regex:"Server: uhttps");
set_mandatory_key( key:"Weborf", regex:"Server: Weborf");
set_mandatory_key( key:"Boa", regex:"Server: Boa/");
set_mandatory_key( key:"minaliC", regex:"Server: minaliC");
set_mandatory_key( key:"tracd", regex:"Server: tracd/");
set_mandatory_key( key:"Wing_FTP_Server", regex:"Server: Wing FTP Server");
set_mandatory_key( key:"httpdx", regex:"httpdx/");
set_mandatory_key( key:"bozohttpd", regex:"Server: bozohttpd/");
set_mandatory_key( key:"AOLserver", regex:"AOLserver/");
set_mandatory_key( key:"SunWWW", regex:"Server: Sun-");
set_mandatory_key( key:"Zeus", regex:"Server: Zeus/");
set_mandatory_key( key:"kolibri", regex:"erver: kolibri");
set_mandatory_key( key:"TopCMM", regex:"Server: TopCMM Server");
set_mandatory_key( key:"onehttpd", regex:"Server: onehttpd");
set_mandatory_key( key:"swebs", regex:"Server: swebs");
set_mandatory_key( key:"JibbleWebServer", regex:"Server: JibbleWebServer");
set_mandatory_key( key:"httpd", regex:"Server: httpd");
set_mandatory_key( key:"MiniWebSvr", regex:"MiniWebSvr");
set_mandatory_key( key:"Yaws", regex:"Server: Yaws/");
set_mandatory_key( key:"Orion", regex:"Server: Orion/");
set_mandatory_key( key:"LiteSpeed", regex:"LiteSpeed");
set_mandatory_key( key:"Play_Framework", regex:"Server: Play. Framework");
set_mandatory_key( key:"WEBrick", regex:"Server: WEBrick");
set_mandatory_key( key:"SaServer", regex:"Server: SaServer");
set_mandatory_key( key:"Varnish", regex:"X-Varnish");
set_mandatory_key( key:"3S_WebServer", regex:"Server: 3S_WebServer");
set_mandatory_key( key:"nostromo", regex:"Server: nostromo");
set_mandatory_key( key:"sharepoint", regex:"sharepoint");
set_mandatory_key( key:"Oracle-Application-Server", regex:"Oracle-Application-Server");
set_mandatory_key( key:"Easy_Chat_Server", regex:"Easy Chat Server");
set_mandatory_key( key:"Hiawatha", regex:"Server: Hiawatha");
set_mandatory_key( key:"SiteScope", regex:"SiteScope");
set_mandatory_key( key:"jHTTPd", regex:"Server: jHTTPd");
set_mandatory_key( key:"Serva32", regex:"Server: Serva32");
set_mandatory_key( key:"CarelDataServer", regex:"Server: CarelDataServer");
set_mandatory_key( key:"TOSHIBA", regex:"Server: TOSHIBA");
set_mandatory_key( key:"Mojolicious", regex:"Server: Mojolicious");
set_mandatory_key( key:"IceWarp", regex:"IceWarp");
set_mandatory_key( key:"Xitami", regex:"Server: Xitami");
set_mandatory_key( key:"wodWebServer", regex:"wodWebServer");
set_mandatory_key( key:"RT-N56U", regex:'Basic realm="RT-N56U"');
set_mandatory_key( key:"HomeSeer", regex:"Server: HomeSeer");
set_mandatory_key( key:"LilHTTP", regex:"Server: LilHTTP");
set_mandatory_key( key:"Univention", regex:"Univention");
set_mandatory_key( key:"DHost", regex:"Server: DHost/[0-9.]+ HttpStk");
set_mandatory_key( key:"surgemail", regex:"surgemail");
set_mandatory_key( key:"TD_Contact_Management_Server", regex:"Server: TD Contact Management Server");
set_mandatory_key( key:"Herberlin_Bremsserver", regex:"Server: Herberlin Bremsserver");
set_mandatory_key( key:"Embedthis-Appweb", regex:"Server: Embedthis-Appweb/");
set_mandatory_key( key:"Indy", regex:"Server: Indy");
set_mandatory_key( key:"TinyServer", regex:"Server: TinyServer");
set_mandatory_key( key:"ALLPLAYER-DLNA", regex:"Server: ALLPLAYER-DLNA");
set_mandatory_key( key:"TVMOBiLi", regex:"TVMOBiLi UPnP Server/");
set_mandatory_key( key:"SpecView", regex:"SpecView");
set_mandatory_key( key:"Mathopd", regex:"Server: Mathopd/");
set_mandatory_key( key:"Sockso", regex:"Server: Sockso");
set_mandatory_key( key:"SentinelKeysServer", regex:"Server: SentinelKeysServer");
set_mandatory_key( key:"fexsrv", regex:"Server: fexsrv");
set_mandatory_key( key:"Pi3Web", regex:"Pi3Web/");
set_mandatory_key( key:"NetDecision-HTTP-Server", regex:"Server: NetDecision-HTTP-Server");
set_mandatory_key( key:"Asterisk", regex:"Server: Asterisk");
set_mandatory_key( key:"PMSoftware-SWS", regex:"Server: PMSoftware-SWS");
set_mandatory_key( key:"lighttpd", regex:"Server: lighttpd");
set_mandatory_key( key:"Null_httpd", regex:"Server: Null httpd");
set_mandatory_key( key:"TVersity_Media_Server", regex:"TVersity Media Server");
set_mandatory_key( key:"WR841N", regex:"WR841N");
set_mandatory_key( key:"IOServer", regex:"Server: IOServer");
set_mandatory_key( key:"Kerio_WinRoute", regex:"Server: Kerio WinRoute Firewall");
set_mandatory_key( key:"webcam_7_xp", regex:"Server: (webcam 7|webcamXP)");
set_mandatory_key( key:"nginx", regex:"Server: nginx");
set_mandatory_key( key:"WindRiver-WebServer", regex:"WindRiver-WebServer");
set_mandatory_key( key:"MobileWebServer", regex:"Server: MobileWebServer/");
set_mandatory_key( key:"MPC-HC", regex:"Server: MPC-HC WebServer");
set_mandatory_key( key:"EAServer", regex:"EAServer");
set_mandatory_key( key:"Rapid_Logic", regex:"Server: Rapid Logic/");
set_mandatory_key( key:"Aastra_6753i", regex:'Basic realm="Aastra 6753i"');
set_mandatory_key( key:"Light_HTTPd", regex:"Light HTTPd");
set_mandatory_key( key:"WebServer_IPCamera_Logo", regex:"Server: WebServer\(IPCamera_Logo\)");
set_mandatory_key( key:"KNet", regex:"Server: KNet");
set_mandatory_key( key:"netcam", regex:'Basic realm="netcam"');
set_mandatory_key( key:"DSL_Router", regex:'WWW-Authenticate: Basic realm="DSL Router"');
set_mandatory_key( key:"EA2700", regex:"EA2700");
set_mandatory_key( key:"TELES_AG", regex:"Server: TELES AG");
set_mandatory_key( key:"Z-World_Rabbit", regex:"Server: Z-World Rabbit");
set_mandatory_key( key:"Nero-MediaHome", regex:"Nero-MediaHome/");
set_mandatory_key( key:"micro_httpd", regex:"Server: micro_httpd");
set_mandatory_key( key:"Monitorix", regex:"Monitorix");
set_mandatory_key( key:"Apache_SVN", regex:"Server: Apache.* SVN");
set_mandatory_key( key:"RT-Device", regex:'Basic realm="RT-');
set_mandatory_key( key:"ADSL_MODEM", regex:'Basic realm="ADSL Modem"');
set_mandatory_key( key:"Nucleus", regex:"Server: Nucleus/");
set_mandatory_key( key:"RT-N10E", regex:'Basic realm="RT-N10E"');
set_mandatory_key( key:"RomPager", regex:"Server: RomPager");
set_mandatory_key( key:"thttpd", regex:"Server: thttpd/");
set_mandatory_key( key:"NETGEAR_DGN", regex:'Basic realm="NETGEAR DGN');
set_mandatory_key( key:"Mbedthis-Appweb", regex:"Server: Mbedthis-Appweb/");
set_mandatory_key( key:"MoxaHttp", regex:"Server: MoxaHttp/");
set_mandatory_key( key:"Web_Server", regex:"Server: Web Server");
set_mandatory_key( key:"thttpd-alphanetworks", regex:"thttpd-alphanetworks");
set_mandatory_key( key:"WNR1000", regex:"NETGEAR WNR1000");
set_mandatory_key( key:"http_server", regex:"Server: http server");
set_mandatory_key( key:"Avtech", regex:"Server:.*Avtech");
set_mandatory_key( key:"Embedded_HTTP_Server", regex:"Server: Embedded HTTP Server");
set_mandatory_key( key:"sdk_for_upnp", regex:"sdk for upnp");
set_mandatory_key( key:"DIR-645", regex:"DIR-645");
set_mandatory_key( key:"Brickcom", regex:"Brickcom");
set_mandatory_key( key:"TD-W8951ND", regex:' Basic realm="TD-W8951ND"');
set_mandatory_key( key:"Resin", regex:"Server: Resin");
set_mandatory_key( key:"Aspen", regex:"Server: Aspen");
set_mandatory_key( key:"miniupnp", regex:"miniupnp/");
set_mandatory_key( key:"DCS-9", regex:'realm="DCS-9');
set_mandatory_key( key:"Cross_Web_Server", regex:"Server: Cross Web Server");
set_mandatory_key( key:"EverFocus", regex:'realm="(EPARA|EPHD|ECOR)[^"]+"');
set_mandatory_key( key:"mini_httpd", regex:"Server: mini_httpd/");
set_mandatory_key( key:"SAP", regex:"server: sap.*");
set_mandatory_key( key:"DIR-6_3_00", regex:"DIR-(6|3)00");
set_mandatory_key( key:"MyNetN679", regex:"MyNetN[6|7|9]");
set_mandatory_key( key:"DeWeS", regex:"Server: DeWeS");
set_mandatory_key( key:"Netwave_IP_Camera", regex:"Netwave IP Camera");
set_mandatory_key( key:"CIMPLICITY", regex:"Server: CIMPLICITY");
set_mandatory_key( key:"Jetty_EAServer", regex:"Server: Jetty\(EAServer/");
set_mandatory_key( key:"intrasrv", regex:"Server: intrasrv");
set_mandatory_key( key:"IQhttp", regex:"Server: IQhttp");
set_mandatory_key( key:"cowboy", regex:"server: cowboy");
set_mandatory_key( key:"Raid_Console", regex:'realm="Raid Console"');
set_mandatory_key( key:"HyNetOS", regex:"HyNetOS");
set_mandatory_key( key:"dcs-lig-httpd", regex:"Server: dcs-lig-httpd");
set_mandatory_key( key:"PRN2001", regex:'Basic realm="PRN2001"');
set_mandatory_key( key:"ZK_Web_Server", regex:"Server: ZK Web Server");
set_mandatory_key( key:"ZXV10_W300", regex:'Basic realm="ZXV10 W300"');
set_mandatory_key( key:"Saia_PCD", regex:"Server: Saia PCD");
set_mandatory_key( key:"Arrakis", regex:"Server: Arrakis");
set_mandatory_key( key:"Mini_web_server", regex:"Server: Mini web server");
set_mandatory_key( key:"SOAPpy", regex:"SOAPpy");
set_mandatory_key( key:"DCS-2103", regex:'Basic realm="DCS-2103"');
set_mandatory_key( key:"WNR1000v3", regex:"NETGEAR WNR1000v3");
set_mandatory_key( key:"SIP-T38G", regex:'Basic realm="Gigabit Color IP Phone SIP-T38G"');
set_mandatory_key( key:"SnIP", regex:'Basic realm="SnIP');
set_mandatory_key( key:"GeoHttpServer", regex:"Server: GeoHttpServer");
set_mandatory_key( key:"Diva_HTTP", regex:"Server: Diva HTTP Plugin");
set_mandatory_key( key:"BlueDragon", regex:"BlueDragon Server");
set_mandatory_key( key:"SonicWALL", regex:"Server: SonicWALL");
set_mandatory_key( key:"Microsoft-HTTPAPI", regex:"Microsoft-HTTPAPI");
set_mandatory_key( key:"efmws", regex:"Server: Easy File Management Web Server");
set_mandatory_key( key:"Polycom_SoundPoint", regex:"erver: Polycom SoundPoint IP");
set_mandatory_key( key:"surgeftp", regex:'Basic realm="surgeftp');
set_mandatory_key( key:"SkyIPCam", regex:'Basic realm="SkyIPCam"');
set_mandatory_key( key:"RT-G32", regex:'Basic realm="RT-G32"');
set_mandatory_key( key:"Router_Webserver", regex:"Server: Router Webserver");
set_mandatory_key( key:"ExaGrid", regex:"Server: ExaGrid");
set_mandatory_key( key:"DSL-N55U", regex:'Basic realm="DSL-N55U');
set_mandatory_key( key:"JAWSJAWS", regex:"erver: JAWS/");
set_mandatory_key( key:"NETGEAR", regex:'Basic realm="NETGEAR');
set_mandatory_key( key:"JVC_API", regex:"Server: JVC.*API Server");
set_mandatory_key( key:"ETag", regex:"ETag:");
set_mandatory_key( key:"BarracudaHTTP", regex:"Server: BarracudaHTTP");
set_mandatory_key( key:"AntServer", regex:"AntServer");
set_mandatory_key( key:"CompaqHTTPServer", regex:"Server: CompaqHTTPServer/");
set_mandatory_key( key:"FlashCom", regex:"erver: FlashCom");
set_mandatory_key( key:"Simple-Server", regex:"erver: Simple-Server");
set_mandatory_key( key:"mod_jk", regex:"mod_jk");
set_mandatory_key( key:"ATS", regex:"Server: ATS/");
set_mandatory_key( key:"iTunes", regex:"DAAP-Server: iTunes/");
set_mandatory_key( key:"BCReport", regex:"BCReport");
set_mandatory_key( key:"CouchDB", regex:"Server: CouchDB/");
set_mandatory_key( key:"X-KACE-Version", regex:"X-KACE-Version");
set_mandatory_key( key:"k1000", regex:"X-DellKACE-Appliance: k1000");
set_mandatory_key( key:"SMC6128L2", regex:'Basic realm="SMC6128L2');
set_mandatory_key( key:"kibana", regex:"kbn-name: kibana");
set_mandatory_key( key:"SiemensGigaset-Server", regex:"Server: SiemensGigaset-Server");
set_mandatory_key( key:"Grandstream_GXP", regex:"Server: Grandstream GXP");
set_mandatory_key( key:"h2o", regex:"Server: h2o");
set_mandatory_key( key:"HHVM", regex:"X-Powered-By: HHVM/");
set_mandatory_key( key:"HFS", regex:"erver: HFS");
set_mandatory_key( key:"BigFixHTTPServer", regex:"Server: BigFixHTTPServer/");
set_mandatory_key( key:"IBM_WebSphere", regex:"Server: IBM WebSphere");
set_mandatory_key( key:"Ingate-SIParator", regex:"erver: Ingate-SIParator");
set_mandatory_key( key:"IAMT", regex:"Server: Intel\(R\) Active Management Technology");
set_mandatory_key( key:"KCEWS", regex:"Server: Kerio Control Embedded Web Server");
set_mandatory_key( key:"Loxone", regex:"Server: Loxone");
set_mandatory_key( key:"MatrixSSL", regex:"Server: .*MatrixSSL");
set_mandatory_key( key:"McAfee_Web_Gateway", regex:"McAfee Web Gateway");
set_mandatory_key( key:"NaviCOPA", regex:"NaviCOPA");
set_mandatory_key( key:"wnr2000", regex:'Basic realm="NETGEAR wnr2000');
set_mandatory_key( key:"nghttpx", regex:"Server: nghttpx");
set_mandatory_key( key:"Norman_Security", regex:"Server: Norman Security/");
set_mandatory_key( key:"NullLogic_Groupware", regex:"NullLogic Groupware");
set_mandatory_key( key:"OpenSSL", regex:"OpenSSL/");
set_mandatory_key( key:"OrientDB", regex:"OrientDB Server");
set_mandatory_key( key:"PanWeb", regex:"Server: PanWeb Server/");
set_mandatory_key( key:"powerfolder", regex:"powerfolder");
set_mandatory_key( key:"PRTG", regex:"Server: PRTG/");
set_mandatory_key( key:"Python", regex:"Python/");
set_mandatory_key( key:"JBoss-EAP", regex:"JBoss-EAP");
set_mandatory_key( key:"MochiWeb", regex:"MochiWeb");
set_mandatory_key( key:"Schneider-WEB", regex:"Server: Schneider-WEB");
set_mandatory_key( key:"Shareaza", regex:"Shareaza");
set_mandatory_key( key:"WebBox", regex:"Server: WebBox");
set_mandatory_key( key:"ILOM-Web-Server", regex:"Server: (Sun|Oracle)-ILOM-Web-Server/");
set_mandatory_key( key:"Apache-Coyote", regex:"Server: Apache-Coyote");
set_mandatory_key( key:"VLC_stream", regex:'Basic realm="VLC stream"');
set_mandatory_key( key:"WSO2_Carbon", regex:"Server: WSO2 Carbon Server");
set_mandatory_key( key:"WSO2_SOA", regex:"Server: WSO2 SOA Enablement Server");
set_mandatory_key( key:"Xerver", regex:"Server: Xerver/");
set_mandatory_key( key:"MLDonkey", regex:"MLDonkey");
set_mandatory_key( key:"myCIO", regex:"myCIO");
set_mandatory_key( key:"ntop", regex:"Server: ntop");
set_mandatory_key( key:"RemotelyAnywhere", regex:"Server: *RemotelyAnywhere");
set_mandatory_key( key:"Sami_HTTP", regex:"Server:.*Sami HTTP Server");
set_mandatory_key( key:"MailEnable", regex:"Server: .*MailEnable");
set_mandatory_key( key:"PHP", regex:"PHP/");
set_mandatory_key( key:"IIS", regex:"IIS");
set_mandatory_key( key:"ZyXEL-RomPager", regex:"ZyXEL-RomPager");
set_mandatory_key( key:"Allegro", regex:"Allegro");
set_mandatory_key( key:"X-Kazaa-Username", regex:"X-Kazaa-Username");
set_mandatory_key( key:"icecast", regex:"icecast/");
set_mandatory_key( key:"vqServer", regex:"Server: vqServer");
set_mandatory_key( key:"dwhttp", regex:"dwhttp/");
set_mandatory_key( key:"ATR-HTTP", regex:"Server: ATR-HTTP-Server");
set_mandatory_key( key:"JRun", regex:"JRun");
set_mandatory_key( key:"WRT54G", regex:'realm="WRT54G"');
set_mandatory_key( key:"Ultraseek", regex:"Server: Ultraseek");
set_mandatory_key( key:"Domino", regex:"Domino");
set_mandatory_key( key:"Roxen", regex:"Roxen");
set_mandatory_key( key:"OracleAS-Web-Cache", regex:"OracleAS-Web-Cache");
set_mandatory_key( key:"WDaemon", regex:"Server: WDaemon/");
set_mandatory_key( key:"Oracle", regex:"Oracle");
set_mandatory_key( key:"Enhydra", regex:"Enhydra");
set_mandatory_key( key:"OmniHTTPd", regex:"OmniHTTPd");
set_mandatory_key( key:"Statistics_Server", regex:"Server: Statistics Server");
set_mandatory_key( key:"mod_python", regex:"mod_python");
set_mandatory_key( key:"Xeneo", regex:"Xeneo/");
set_mandatory_key( key:"RemotelyAnywhere", regex:"RemotelyAnywhere");
set_mandatory_key( key:"4D_WebSTAR", regex:"^Server: 4D_WebSTAR");
set_mandatory_key( key:"limewire", regex:"limewire");
set_mandatory_key( key:"TinyWeb", regex:"Server:.*TinyWeb/");
set_mandatory_key( key:"BadBlue", regex:"BadBlue");
set_mandatory_key( key:"Jetadmin", regex:"HP Web Jetadmin");
set_mandatory_key( key:"VisualRoute", regex:"Server: VisualRoute");
set_mandatory_key( key:"SimpleServer", regex:"SimpleServer");
set_mandatory_key( key:"LocalWEB2000", regex:"Server: .*LocalWEB2000");
set_mandatory_key( key:"LabVIEW", regex:"Server: LabVIEW");
set_mandatory_key( key:"shoutcast", regex:"shoutcast");
set_mandatory_key( key:"+WN", regex:"Server: +WN");
set_mandatory_key( key:"Lotus", regex:"Lotus");
set_mandatory_key( key:"Netscape_iPlanet", regex:"(Netscape|iPlanet)");
set_mandatory_key( key:"linksys", regex:"linksys");
set_mandatory_key( key:"oaohi", regex:"Oracle Applications One-Hour Install");
set_mandatory_key( key:"Web_Server_4D", regex:"Web_Server_4D");
set_mandatory_key( key:"eMule", regex:"eMule");
set_mandatory_key( key:"Novell_Netware", regex:"(Novell|Netware)");
set_mandatory_key( key:"W4E", regex:"WebServer 4 Everyone");
set_mandatory_key( key:"vncviewer_jc", regex:"vncviewer\.(jar|class)");
set_mandatory_key( key:"MagnoWare", regex:"Server: MagnoWare");
set_mandatory_key( key:"ELOG_HTTP", regex:"Server: ELOG HTTP");
set_mandatory_key( key:"RTC", regex:"Server: RTC/");
set_mandatory_key( key:"ZendServer", regex:"ZendServer");
set_mandatory_key( key:"SWS", regex:"Server: SWS-");
set_mandatory_key( key:"RealVNC", regex:"RealVNC/");
set_mandatory_key( key:"PST10", regex:"Server: PST10 WebServer");
set_mandatory_key( key:"Anti-Web", regex:"Server: Anti-Web");
set_mandatory_key( key:"Unspecified-UPnP", regex:"Server: Unspecified, UPnP");
set_mandatory_key( key:"debut", regex:"Server: debut/");
set_mandatory_key( key:"libsoup", regex:"Server: (soup-transcode-proxy )?libsoup");
set_mandatory_key( key:"spidercontrol-scada", regex:"Server: SCADA.*(powered by SpiderControl TM)");
set_mandatory_key( key:"StorageGRID", regex:"Server: StorageGRID");
set_mandatory_key( key:"NetApp", regex: "Server: NetApp");

exit( 0 );
